package acme

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// 将证书和密钥 PEM 写入指定的路径。
func DeployCertFiles(certPEM, keyPEM, certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("deploy paths are required")
	}

	// 确保父目录存在
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}

	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

// 向 nginx 发送重新加载信号。
func ReloadNginx() error {
	return ReloadNginxContext(context.Background())
}

// ReloadNginxContext reloads nginx without allowing a broken service manager
// or init script to block the caller forever.
func ReloadNginxContext(ctx context.Context) error {
	// 首先尝试常见的 nginx 二进制路径，然后回退到 systemctl
	for _, nginxBin := range []string{"/usr/local/nginx/sbin/nginx", "nginx"} {
		if path, err := exec.LookPath(nginxBin); err == nil {
			cmd := exec.CommandContext(ctx, path, "-s", "reload")
			reloadOutput, reloadErr := cmd.CombinedOutput()
			if reloadErr == nil {
				return nil
			}

			// nginx.pid 由运行中的 master 进程创建，不能手工伪造。reload 失败且
			// systemd 确认服务未运行时，按首次部署处理并启动服务。
			if systemctl, serr := exec.LookPath("systemctl"); serr == nil {
				if activeErr := exec.CommandContext(ctx, systemctl, "is-active", "--quiet", "nginx").Run(); activeErr != nil {
					if _, startErr := exec.CommandContext(ctx, systemctl, "start", "nginx").CombinedOutput(); startErr != nil {
						// 容器里可能装有 systemctl 二进制但没有运行 systemd；继续尝试
						// 裸 nginx 启动，最终错误由下面的启动命令给出。
					} else {
						return nil
					}
				} else {
					// 服务实际处于 active，说明不是“首次启动缺 PID”；保留原 reload
					// 错误（通常是配置校验失败），不能再启动第二个 master 掩盖根因。
					return fmt.Errorf("nginx reload: %s: %w", string(reloadOutput), reloadErr)
				}
			}

			// 无 systemd（如容器）且没有运行中的 master 时，直接启动 nginx。
			if output, startErr := exec.CommandContext(ctx, path).CombinedOutput(); startErr != nil {
				return fmt.Errorf("nginx start after reload failed: %s: %w", string(output), startErr)
			}
			return nil
		}
	}
	// 后备：systemctl
	cmd := exec.CommandContext(ctx, "systemctl", "reload", "nginx")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx reload via systemctl: %s: %w", string(output), err)
	}
	return nil
}

// RestartXray通过systemctl重新启动xray服务。
func RestartXray() error {
	return RestartXrayContext(context.Background())
}

func RestartXrayContext(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "xray")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("xray restart: %s: %w", string(output), err)
	}
	return nil
}

// 部署写入证书文件并可选择重新加载服务。
// reloadTarget：“nginx”、“xray”、“两者”或“无”。
func Deploy(certPEM, keyPEM, certPath, keyPath, reloadTarget string) error {
	return DeployContext(context.Background(), certPEM, keyPEM, certPath, keyPath, reloadTarget)
}

func DeployContext(ctx context.Context, certPEM, keyPEM, certPath, keyPath, reloadTarget string) error {
	if err := DeployCertFiles(certPEM, keyPEM, certPath, keyPath); err != nil {
		return err
	}

	switch reloadTarget {
	case "nginx":
		return ReloadNginxContext(ctx)
	case "xray":
		return RestartXrayContext(ctx)
	case "both":
		if err := ReloadNginxContext(ctx); err != nil {
			return err
		}
		return RestartXrayContext(ctx)
	}
	return nil
}
