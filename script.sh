#!/bin/bash

# Header
echo "===== Docker Security Check ====="

# RULE #0 - Check Docker & OS updates
echo "\n[1] Checking Docker & OS updates..."
docker_version=$(docker --version)
os_version=$(uname -a)
echo "Docker Version: $docker_version"
echo "OS Version: $os_version"
echo "Checking for updates..."

if command -v apt > /dev/null; then
    sudo apt update > /dev/null 2>&1 && sudo apt list --upgradable | grep docker
elif command -v yum > /dev/null; then
    sudo yum check-update docker
elif command -v dnf > /dev/null; then
    sudo dnf check-update docker
else
    echo "Package manager not supported for automatic update check."
fi

# RULE #1 - Check Docker socket exposure
echo "\n[2] Checking if Docker socket is exposed..."
if [ -e "/var/run/docker.sock" ]; then
    echo "[WARNING] Docker socket (/var/run/docker.sock) is exposed!"
else
    echo "[OK] Docker socket is not exposed."
fi

# Check running containers
running_containers=$(docker ps -q)
if [ -z "$running_containers" ]; then
    echo "\nNo running containers found. Exiting."
    exit 0
fi

for container in $running_containers; do
    echo "\n---------------------------"
    echo "Checking container: $container"

    # RULE #2 - Set a user
    user=$(docker inspect --format '{{.Config.User}}' $container)
    if [ -z "$user" ]; then
        echo "[WARNING] Container $container is running as root!"
    else
        echo "[OK] Container is running as user: $user"
    fi

    # RULE #3 - Limit capabilities
    cap_add=$(docker inspect --format '{{.HostConfig.CapAdd}}' $container)
    if [ "$cap_add" != "<no value>" ] && [ "$cap_add" != "[]" ]; then
        echo "[WARNING] Container $container has additional capabilities: $cap_add"
    else
        echo "[OK] No additional capabilities found."
    fi

    # RULE #4 - Prevent privilege escalation
    privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' $container)
    if [ "$privileged" == "true" ]; then
        echo "[WARNING] Container $container is running in privileged mode!"
    else
        echo "[OK] Container is not running in privileged mode."
    fi

    # RULE #5 - Check network mode
    network_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' $container)
    if [ "$network_mode" == "host" ]; then
        echo "[WARNING] Container $container is using host networking!"
    else
        echo "[OK] Isolated networking mode: $network_mode"
    fi

    # RULE #6 - Check security options
    security_opt=$(docker inspect --format '{{.HostConfig.SecurityOpt}}' $container)
    if [ "$security_opt" == "<no value>" ] || [ "$security_opt" == "[]" ]; then
        echo "[WARNING] No Seccomp/AppArmor/SELinux enabled!"
    else
        echo "[OK] Security options applied: $security_opt"
    fi

    # RULE #7 - Check resource limits
    mem_limit=$(docker inspect --format '{{.HostConfig.Memory}}' $container)
    cpu_shares=$(docker inspect --format '{{.HostConfig.CpuShares}}' $container)
    restart_policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' $container)

    [ "$mem_limit" == "0" ] && echo "[WARNING] No memory limit set!" || echo "[OK] Memory limit: $mem_limit"
    [ "$cpu_shares" == "0" ] && echo "[WARNING] No CPU limit set!" || echo "[OK] CPU limit: $cpu_shares"
    [ "$restart_policy" == "always" ] && echo "[WARNING] Restart policy is 'always'!" || echo "[OK] Restart policy: $restart_policy"

    # RULE #8 - Check read-only filesystem
    readonly_fs=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' $container)
    [ "$readonly_fs" == "true" ] && echo "[OK] Read-only filesystem enabled." || echo "[WARNING] Read-only filesystem not enabled!"

    # RULE #10 - Check logging level
    log_level=$(docker info --format '{{.LoggingDriver}}')
    [ "$log_level" != "json-file" ] && echo "[WARNING] Logging driver not set to json-file!" || echo "[OK] Logging level is correct."

    # RULE #11 - Check rootless mode
    rootless_check=$(docker info | grep "rootless" | awk '{print $2}')
    [ "$rootless_check" == "true" ] && echo "[OK] Running in rootless mode." || echo "[WARNING] Not running in rootless mode!"

    # RULE #12 - Check secrets in environment variables
    env_vars=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' $container)
    if [ -n "$env_vars" ]; then
        echo "Environment Variables:"
        echo "----------------------------"
        printf "%-30s | %-50s\n" "Key" "Value"
        echo "----------------------------"
        echo "$env_vars" | awk -F= '{printf "%-30s | %-50s\n", $1, $2}'
        echo "----------------------------"

        secrets=$(echo "$env_vars" | grep -i "secret")
        [ -n "$secrets" ] && echo "[WARNING] Secrets found in environment variables!" || echo "[OK] No hardcoded secrets."
    else
        echo "[OK] No environment variables found."
    fi

done

echo "\n===== Docker Security Check Completed ====="
