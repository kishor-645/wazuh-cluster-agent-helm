docker build --no-cache -t your-registry.azurecr.io/wazuh-agent:$1 .
docker push your-registry.azurecr.io/wazuh-agent:$1
