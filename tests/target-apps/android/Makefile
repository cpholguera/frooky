REPO_URL  := https://github.com/cpholguera/mas-app-android
BUILD_DIR := $(CURDIR)/build
DIST_DIR  := $(CURDIR)/dist
CLONE_DIR := $(BUILD_DIR)/mas-app-android
APK_SRC   := $(CLONE_DIR)/app/build/outputs/apk/debug/app-debug.apk
APK_DST   := $(DIST_DIR)/MASTestApp.apk

JAVA_HOME ?= $(shell java -XshowSettings:property -version 2>&1 | grep java.home | awk '{print $$3}')

.PHONY: build clean

build: clean $(BUILD_DIR) $(DIST_DIR)
	git clone $(REPO_URL) $(CLONE_DIR)

	@[ -f "$(APP_DIR)/MastgTest.kt" ] && \
		cp -f "$(APP_DIR)/MastgTest.kt" \
			"$(CLONE_DIR)/app/src/main/java/org/owasp/mastestapp/MastgTest.kt" && \
		echo "Copied MastgTest.kt" || true

	@[ -f "$(APP_DIR)/build.gradle.kts.libs" ] && \
		sed -i "s|// ADD_LIBS_HERE|$$(cat "$(APP_DIR)/build.gradle.kts.libs")|" \
			"$(CLONE_DIR)/app/build.gradle.kts" && \
		echo "Replaced libs in build.gradle.kts" || true
	
	cd $(CLONE_DIR) && JAVA_HOME=$(JAVA_HOME) ./gradlew assembleDebug
	mv $(APK_SRC) $(APK_DST)
	@echo "APK available at: $(APK_DST)"


$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR)
