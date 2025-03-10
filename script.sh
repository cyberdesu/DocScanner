#!/bin/bash

echo "===== Docker Security Check ====="

### RULE #0 - Keep Host and Docker up to date ###
echo "[1] Checking Docker & OS updates..."
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

### RULE #1 - Do not expose the Docker daemon socket ###
echo "[2] Checking if Docker socket is exposed..."
if [ -e "/var/run/docker.sock" ]; then
    echo "[WARNING] Docker socket (/var/run/docker.sock) is exposed!"
else
    echo "[OK] Docker socket is not exposed."
fi

### RULE #2 to RULE #12 - Checking all running containers ###
running_containers=$(docker ps -q)
if [ -z "$running_containers" ]; then
    echo "No running containers found."
    exit 0
fi

for container in $running_containers; do
    echo "---------------------------"
    echo "Checking container: $container"

    ### RULE #2 - Set a user ###
    user=$(docker inspect --format '{{.Config.User}}' $container)
    if [ -z "$user" ]; then
        echo "[WARNING] Container $container is running as root!"
    else
        echo "[OK] Container is running as user: $user"
    fi

    ### RULE #3 - Limit capabilities ###
    cap_add=$(docker inspect --format '{{.HostConfig.CapAdd}}' $container)
    if [ "$cap_add" != "<no value>" ] && [ "$cap_add" != "[]" ]; then
        echo "[WARNING] Container $container has additional capabilities: $cap_add"
    else
        echo "[OK] No additional capabilities found."
    fi

    ### RULE #4 - Prevent in-container privilege escalation ###
    no_new_priv=$(docker inspect $container --format '{{if .HostConfig.NoNewPrivileges}}{{.HostConfig.NoNewPrivileges}}{{else}}false{{end}}')
    if [ "$no_new_priv" == "true" ]; then
        echo "[OK] Container $container has 'no-new-privileges' enabled."
    else
        echo "[WARNING] Container $container allows privilege escalation!"
    fi

    ### RULE #5 - Check Inter-Container Connectivity ###
    network_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' $container)
    if [ "$network_mode" == "host" ]; then
        echo "[WARNING] Container $container is using host networking!"
    else
        echo "[OK] Container $container has isolated networking: $network_mode"
    fi

    ### RULE #6 - Use Linux Security Module (seccomp/AppArmor/SELinux) ###
    security_opt=$(docker inspect --format '{{.HostConfig.SecurityOpt}}' $container)
    if [ "$security_opt" == "<no value>" ] || [ "$security_opt" == "[]" ]; then
        echo "[WARNING] Container $container is running without Seccomp/AppArmor/SELinux!"
    else
        echo "[OK] Security modules applied: $security_opt"
    fi

    ### RULE #7 - Limit resources (memory, CPU, file descriptors, processes, restarts) ###
    mem_limit=$(docker inspect --format '{{.HostConfig.Memory}}' $container)
    cpu_shares=$(docker inspect --format '{{.HostConfig.CpuShares}}' $container)
    restart_policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' $container)
    
    if [ "$mem_limit" == "0" ]; then
        echo "[WARNING] No memory limit set for container $container!"
    else
        echo "[OK] Memory limit: $mem_limit"
    fi
    
    if [ "$cpu_shares" == "0" ]; then
        echo "[WARNING] No CPU limit set for container $container!"
    else
        echo "[OK] CPU limit: $cpu_shares"
    fi
    
    if [ "$restart_policy" == "always" ]; then
        echo "[WARNING] Container $container restart policy is 'always'!"
    else
        echo "[OK] Restart policy: $restart_policy"
    fi

    ### RULE #8 - Set filesystem and volumes to read-only ###
    readonly_fs=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' $container)
    if [ "$readonly_fs" == "true" ]; then
        echo "[OK] Container $container has a read-only filesystem."
    else
        echo "[WARNING] Container $container does not have a read-only filesystem!"
    fi

    ### RULE #10 - Keep the Docker daemon logging level at info ###
    log_level=$(docker info --format '{{.LoggingDriver}}')
    if [[ "$log_level" != "json-file" ]]; then
        echo "[WARNING] Docker logging driver is not set to json-file (default logging mode)."
    else
        echo "[OK] Docker logging level is set correctly."
    fi

    ### RULE #11 - Run Docker in rootless mode ###
    rootless_check=$(docker info | grep "rootless" | awk '{print $2}')
    if [ "$rootless_check" == "true" ]; then
        echo "[OK] Docker is running in rootless mode."
    else
        echo "[WARNING] Docker is NOT running in rootless mode!"
    fi

    ### RULE #12 - Utilize Docker Secrets for Sensitive Data Management ###
    secrets=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' $container | grep -i "secret")
    if [ -n "$secrets" ]; then
        echo "[WARNING] Environment variables contain 'secret', ensure it is stored securely!"
    else
        echo "[OK] No hardcoded secrets found in environment variables."
    fi
done

echo "===== Docker Security Check Completed ====="
