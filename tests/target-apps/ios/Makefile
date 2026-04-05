REPO_URL  := https://github.com/cpholguera/mas-app-ios
BUILD_DIR := $(CURDIR)/build
DIST_DIR  := $(CURDIR)/dist
CLONE_DIR := $(BUILD_DIR)/mas-app-ios
DERIVED_DATA := $(BUILD_DIR)/DerivedData
IOS_APP_SRC  := $(DERIVED_DATA)/Build/Products/Debug-iphonesimulator
IOS_APP_DST  := $(DIST_DIR)/

.PHONY: build clean

build: clean $(BUILD_DIR) $(DIST_DIR)
	@[ -n "$(GITHUB_ENV_FILE)" ] && echo "SIM_ID=$$SIM_ID" >> $(GITHUB_ENV_FILE) || true
	
	git clone $(REPO_URL) $(CLONE_DIR)

	@[ -f "$(APP_DIR)/MastgTest.swift" ] && \
		cp -f "$(APP_DIR)/MastgTest.swift" \
			"$(CLONE_DIR)/MASTestApp/MastgTest.swift" && \
		echo "Copied MastgTest.swift" || true

	cp $(CLONE_DIR)/.github/Local.xcconfig.ci $(CLONE_DIR)/Local.xcconfig

	cd $(CLONE_DIR) && \
		IOS_SCHEME=$$(xcodebuild -list -json | jq -r '.project.targets[0]') && \
		SIM_ID=$$(xcrun simctl list devices available -j | \
			jq -r '[.devices | to_entries[] | select(.key | contains("iOS")) | .value[]] | map(select(.isAvailable == true)) | first | .udid') && \
		echo "Using scheme: $$IOS_SCHEME" && \
		echo "SIM_ID=$$SIM_ID" >> $(GITHUB_ENV_FILE) && \
		xcodebuild build \
			-project "MASTestApp.xcodeproj" \
			-scheme "$$IOS_SCHEME" \
			-destination "platform=iOS Simulator,id=$$SIM_ID" \
			-derivedDataPath "$(DERIVED_DATA)" \
			CODE_SIGN_IDENTITY="" \
			CODE_SIGNING_REQUIRED=NO \
			CODE_SIGNING_ALLOWED=NO

	mkdir -p $(IOS_APP_DST)
	cp -r $(IOS_APP_SRC)/*.app $(IOS_APP_DST)/
	@echo "iOS app available at: $(IOS_APP_DST)"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR)
