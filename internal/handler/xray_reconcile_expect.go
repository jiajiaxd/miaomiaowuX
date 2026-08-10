package handler

import (
	"time"

	"miaomiaowux/internal/storage"
)

// 期望状态推导 —— XrayClientReconciler 的决策核心,刻意做成**纯函数**,不碰 DB / 不碰 agent,
// 于是「什么该存在、什么不该存在」这条最容易出灾难的逻辑可以被表驱动测试穷举。
//
// 决策单元是 **email**,不是 (server, inbound_tag)。原因:routed 子账号的 client 就住在
// 父物理入站上(removeUserFromRoutedNode 用的是同一个 (serverID, routed.InboundTag)),
// 所以同一个 inbound 上可以同时有 alice__vless-tcp(physical) 和 alice__myrelay(routed)。
// 任何"用户 alice 在 (S,X) 上应当恰好有一个 client"的推理都是错的。

// inboundKey 标识一个物理入站。凭据绑在入站上而非节点上 —— both(v4/v6) 的两个节点
// 共享同一 (server, inbound_tag),用 map 收敛后天然只算一次。
type inboundKey struct {
	ServerID   int64
	InboundTag string
}

// userExpectation 是某用户的权威期望集。
//
// decided=false 表示「无意见」:既不加也不删。这不是"空期望"的同义词 —— 空期望(decided=true,
// 集合为空)意味着"该用户不该有任何 client,可以删";无意见意味着"我不知道,别动"。
// 把这两者混为一谈就是删光用户 client 的最短路径。
type userExpectation struct {
	physical map[inboundKey]bool // 期望存在的物理入站(email = username__inboundTag)
	routed   map[int64]bool      // 期望 active 的 routed 节点 ID(email 取 user_subaccounts.email)
	decided  bool
}

func (e userExpectation) hasPhysical(k inboundKey) bool { return e.physical[k] }
func (e userExpectation) hasRouted(nodeID int64) bool   { return e.routed[nodeID] }

// computeUserExpectation 推导单个用户的期望状态。
//
// pkgNodes/pkgErr 来自 GetPackageNodesStrict(严格解析);pkgErr != nil 一律退化为「无意见」。
// overLimit 来自 IsUserOverLimit。
//
// ⚠️ overLimit 与 !IsActive 是**必需输入,不是细化**:
// 超额(traffic_limit_enforcer.go 的 isOverLimit && !wasOverLimit)与禁用(users.go 的状态切换)
// 摘除 client 后都**保留** user_inbound_configs 与 package_id,且两个移除器都是**边沿触发**
// (超额踢完即置 is_over_limit=true,此后 !wasOverLimit 永假;禁用纯事件驱动)。
// 若期望状态只看"有没有有效套餐",reconciler 会每轮把这两类用户的 client 加回去,
// 而没有任何东西会再把他们踢出去 → 超额用户永久免费流量、被封用户自动解封。
func computeUserExpectation(
	u storage.User,
	now time.Time,
	pkgNodes []int64,
	pkgErr error,
	overLimit bool,
	nodesByID map[int64]storage.Node,
	serverIDByName map[string]int64,
) userExpectation {
	noOpinion := userExpectation{decided: false}

	// —— 无意见闸门(顺序重要:先 skip,再判抑制) ——

	// admin 的 client 不由套餐驱动:EnsureAdminInboundClient 刻意允许同一 inbound 上多行
	// (traffic.go 注释"一个 inbound 上多个 client 各算一行(不强 UNIQUE)"),没有套餐形状的东西可比。
	if u.Role != storage.RoleUser {
		return noOpinion
	}
	// 套餐读不出 / 解析可疑 → 绝不删。这是"期望塌成空"的第一道防线。
	if pkgErr != nil {
		return noOpinion
	}

	empty := userExpectation{
		physical: map[inboundKey]bool{},
		routed:   map[int64]bool{},
		decided:  true,
	}

	// —— 抑制态:期望空集(允许删,禁止加) ——

	if !u.IsActive {
		return empty // 禁用 —— 同时也是 users.go 那条"失败只 log、无重试"路径的重试
	}
	if overLimit {
		return empty // 超额 —— 同上,补上 enforcer 边沿触发够不到的地方
	}
	if u.PackageID <= 0 {
		return empty // 无套餐,含 enforcer 到期时 RemovePackageFromUser 清过 package_id 的用户
	}
	// 到期判定必须与 traffic_limit_enforcer.go 的 `now.After(*user.PackageEndDate)` **逐字一致**,
	// 任何偏差(如改成 Before / 截断到日)都会造成 enforcer 恢复、reconciler 删除的永久拉锯。
	if u.PackageEndDate != nil && now.After(*u.PackageEndDate) {
		return empty
	}

	// —— 正常:套餐节点 → 期望集 ——

	exp := userExpectation{
		physical: map[inboundKey]bool{},
		routed:   map[int64]bool{},
		decided:  true,
	}
	for _, nodeID := range pkgNodes {
		node, ok := nodesByID[nodeID]
		if !ok {
			continue // 孤儿 node id:跳过该节点,不牵连兄弟节点
		}
		if node.OriginalServer == "" {
			continue
		}
		sid, ok := serverIDByName[node.OriginalServer]
		if !ok {
			continue // server 已删/改名 → 跳过,不据此删 client
		}
		if node.NodeType == "routed" {
			// routed_owner='user' 的私有出站不进套餐池、不由 pkg.Nodes 驱动
			// (它走 suspend/resumeUserPrivateRouted,期望由套餐有效性间接决定)。
			// 这里只认 shared。
			if node.RoutedOwner == "user" {
				continue
			}
			exp.routed[node.ID] = true
			continue
		}
		if node.InboundTag == "" {
			continue // 镜像 packages.go 的 add 路径:无 tag 不下发
		}
		// node.Enabled 刻意不看 —— add 路径也不看它。按它过滤会凭空制造删除:
		// 禁用一个节点不会让 packages.go 摘 client,reconciler 也就不该摘。
		exp.physical[inboundKey{ServerID: sid, InboundTag: node.InboundTag}] = true
	}
	return exp
}

// canonicalPhysicalEmail 构造物理入站 client 的规范 email。
//
// ⚠️ **必须与 getOrCreateInboundCredential(packages.go)的构造逐字节一致**。
// 这是 reconciler 与 OrphanXrayClientCleaner 不相交的前提:cleaner 的 shouldKeep 靠
// ResolveUsernameByEmail 的 `instr(?, username || '__') = 1` 命中 users 表来放行。
// 一旦这里发明了别的 email 格式,reconciler 加出来的 client 就会被 cleaner 当孤儿删掉,
// 两个 job 每天互删互加 —— 所以有一条测试专门钉死这个不变量。
func canonicalPhysicalEmail(username, inboundTag string) string {
	return username + "__" + inboundTag
}
