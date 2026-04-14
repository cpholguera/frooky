REPO_URL  := https://github.com/cpholguera/mas-app-android
DIST_DIR  := $(CURDIR)/dist

ifdef TARGET_APP
BUILD_DIR := $(CURDIR)/$(TARGET_APP)/build
CLONE_DIR := $(BUILD_DIR)/mas-app-android
APK_SRC   := $(CLONE_DIR)/app/build/outputs/apk/debug/app-debug.apk
APK_DST   := $(DIST_DIR)/$(TARGET_APP).target-app.apk
endif

JAVA_HOME ?= $(shell java -XshowSettings:property -version 2>&1 | grep java.home | awk '{print $$3}')

BUNDLE_ID := org.owasp.mastestapp

ALL_APPS := $(shell find . -maxdepth 1 -mindepth 1 -type d \
	! -name dist ! -name '.*' \
	-exec basename {} \;)

.PHONY: build build-all install install-all clean clean-all

build: $(BUILD_DIR) $(DIST_DIR)
	@[ -n "$(TARGET_APP)" ] || { echo "ERROR: TARGET_APP is required. Usage: make build TARGET_APP=<name>"; exit 1; }

	@if [ ! -d "$(CLONE_DIR)/.git" ]; then \
		git clone $(REPO_URL) $(CLONE_DIR); \
	else \
		echo "Repo already cloned, skipping git clone."; \
	fi

	@[ -n "$(TARGET_APP)" ] && \
		perl -i -pe 's|applicationId = "org.owasp.mastestapp"|applicationId = "$(subst -,_,$(TARGET_APP)).mastestapp"|' \
			"$(CLONE_DIR)/app/build.gradle.kts" && \
		echo "Set applicationId to $(subst -,_,$(TARGET_APP)).mastestapp" || true

	@[ -f "$(TARGET_APP)/MastgTest.kt" ] && \
		cp -f "$(TARGET_APP)/MastgTest.kt" \
			"$(CLONE_DIR)/app/src/main/java/org/owasp/mastestapp/MastgTest.kt" && \
		echo "Copied MastgTest.kt" || true

	@[ -f "$(TARGET_APP)/build.gradle.kts.libs" ] && \
		perl -i -pe "s|// ADD_LIBS_HERE|$$(cat "$(TARGET_APP)/build.gradle.kts.libs")|" \
			"$(CLONE_DIR)/app/build.gradle.kts" && \
		echo "Replaced libs in build.gradle.kts" || true

	cd $(CLONE_DIR) && JAVA_HOME="$(JAVA_HOME)" ./gradlew assembleDebug
	mv $(APK_SRC) $(APK_DST)
	@echo "APK available at: $(APK_DST)"

build-all:
	@for app in $(ALL_APPS); do \
		echo "=== Building $$app ==="; \
		$(MAKE) build TARGET_APP=$$app; \
	done

install:
	@[ -n "$(TARGET_APP)" ] || { echo "ERROR: TARGET_APP is required. Usage: make install TARGET_APP=<name>"; exit 1; }
	adb install -r "$(APK_DST)"

install-all:
	@for app in $(ALL_APPS); do \
		echo "=== Installing $$app ==="; \
		$(MAKE) install TARGET_APP=$$app; \
	done

clean:
	@[ -n "$(TARGET_APP)" ] || { echo "ERROR: TARGET_APP is required. Usage: make clean TARGET_APP=<name>"; exit 1; }
	rm -rf $(BUILD_DIR)

clean-all:
	@for app in $(ALL_APPS); do \
		echo "=== Cleaning $$app ==="; \
		$(MAKE) clean TARGET_APP=$$app; \
	done
	rm -rf $(DIST_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)
