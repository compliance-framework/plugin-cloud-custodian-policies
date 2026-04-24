# Check if OPA CLI is installed
OPA := $(shell command -v opa 2> /dev/null)
ifeq ($(OPA),)
$(error "opa CLI not found. Please install it: https://www.openpolicyagent.org/docs/latest/cli/")
endif

##@ Help
help: ## Display this concise help, ie only the porcelain target
	@awk 'BEGIN {FS = ":.*##"; printf "\033[1mUsage\033[0m\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

help-all: ## Display all help items, ie including plumbing targets
	@awk 'BEGIN {FS = ":.*#"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?#/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^#@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Policies
test: ## Test policy files
	@$(OPA) test policies

validate: ## Validate policy files
	@$(OPA) check policies

clean: # Cleanup build artifacts
	@rm -f dist/*

build: clean ## Build the policy bundle
	@mkdir -p dist/
	@$(OPA) build -b policies -o dist/bundle.tar.gz
