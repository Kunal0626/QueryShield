# QueryShield build.
#
# Plain javac + make on purpose: the whole build is readable top to bottom,
# and the point of this project is "I wrote the algorithm by hand", not
# "I configured a build tool". Nothing here needs installing beyond the JDK
# that is already on the machine. `make deps` fetches exactly two jars from
# Maven Central and verifies each against a pinned SHA-256 before use.
#
# Targets:
#   make deps      download + checksum-verify the two dependency jars
#   make build     compile main sources  -> out/main
#   make test      compile + run JUnit 5 tests
#   make victim    run the (deliberately vulnerable) demo app   on :8081
#   make proxy     run the QueryShield proxy                    on :8080  (phase 7)
#   make eval      run the offline evaluation harness                     (phase 5+)
#   make e2e       end-to-end: exploits blocked via proxy, + --safe comparison
#   make loadtest  run the throughput/latency load generator              (phase 9)
#   make clean     remove compiled output
#   make distclean also remove downloaded jars

# ----------------------------------------------------------------------------
# Toolchain. We compile with whatever JDK is on PATH but target Java 21 (the
# current LTS) so a clean clone builds on any 21+ JDK, not only this machine's.
# ----------------------------------------------------------------------------
JAVAC        := javac
JAVA         := java
RELEASE      := 21

SRC_MAIN     := src/main/java
SRC_TEST     := src/test/java
RES_MAIN     := src/main/resources
OUT_MAIN     := out/main
OUT_TEST     := out/test

# ----------------------------------------------------------------------------
# Dependencies. Two leaf jars, no transitive deps, so no resolver is needed.
# Versions and checksums are pinned; `make deps` refuses a jar whose hash does
# not match. Checksums were recorded on the machine that first fetched them:
#   macOS arm64, 2026-11-06, via `shasum -a 256`.
# ----------------------------------------------------------------------------
LIB          := lib
MAVEN        := https://repo1.maven.org/maven2

CJ_VER       := 9.1.0
CJ_JAR       := $(LIB)/mysql-connector-j-$(CJ_VER).jar
CJ_URL       := $(MAVEN)/com/mysql/mysql-connector-j/$(CJ_VER)/mysql-connector-j-$(CJ_VER).jar
CJ_SHA256    := 8776e2ebc46072c9a47ea59d98298c4273bd9f16a7b26b5dfa4744535aa26c62

JU_VER       := 1.11.3
JU_JAR       := $(LIB)/junit-platform-console-standalone-$(JU_VER).jar
JU_URL       := $(MAVEN)/org/junit/platform/junit-platform-console-standalone/$(JU_VER)/junit-platform-console-standalone-$(JU_VER).jar
JU_SHA256    := 33440476714985bda2584ed6c70d0d877085012343be67e961dcf80dac596227

# Classpath for compiling/running main code (JDBC driver only).
CP_MAIN      := $(OUT_MAIN):$(RES_MAIN):$(CJ_JAR)
# Classpath for tests adds the compiled tests and the JUnit launcher.
CP_TEST      := $(OUT_TEST):$(CP_MAIN):$(JU_JAR)

# All main/test sources, discovered rather than listed, so new files are picked
# up automatically.
MAIN_SRCS    := $(shell find $(SRC_MAIN) -name '*.java' 2>/dev/null)
TEST_SRCS    := $(shell find $(SRC_TEST) -name '*.java' 2>/dev/null)

.DEFAULT_GOAL := build
.PHONY: deps build test victim proxy eval e2e loadtest clean distclean help

# ----------------------------------------------------------------------------
help:
	@grep -E '^#   make ' Makefile | sed 's/^#   /  /'

# --- dependencies -----------------------------------------------------------
deps: $(CJ_JAR) $(JU_JAR)

$(CJ_JAR):
	@mkdir -p $(LIB)
	@echo "fetch  $(notdir $@)"
	@curl -fsSL -o $@ $(CJ_URL)
	@$(call verify_sha,$@,$(CJ_SHA256))

$(JU_JAR):
	@mkdir -p $(LIB)
	@echo "fetch  $(notdir $@)"
	@curl -fsSL -o $@ $(JU_URL)
	@$(call verify_sha,$@,$(JU_SHA256))

# verify_sha <file> <expected-hex>: abort (and delete the bad file) on mismatch.
define verify_sha
	actual=$$(shasum -a 256 $(1) | awk '{print $$1}'); \
	if [ "$$actual" != "$(2)" ]; then \
	  echo "CHECKSUM MISMATCH for $(1)"; \
	  echo "  expected $(2)"; \
	  echo "  actual   $$actual"; \
	  rm -f $(1); exit 1; \
	fi; \
	echo "verify $(notdir $(1))  ok"
endef

# --- compile ----------------------------------------------------------------
build: deps
	@mkdir -p $(OUT_MAIN)
	@echo "javac  main ($(words $(MAIN_SRCS)) files, --release $(RELEASE))"
	@$(JAVAC) --release $(RELEASE) -Xlint:all -d $(OUT_MAIN) -cp "$(CP_MAIN)" $(MAIN_SRCS)
	@cp -R $(RES_MAIN)/. $(OUT_MAIN)/ 2>/dev/null || true

# --- tests ------------------------------------------------------------------
test: build
	@mkdir -p $(OUT_TEST)
	@echo "javac  test ($(words $(TEST_SRCS)) files)"
	@$(JAVAC) --release $(RELEASE) -d $(OUT_TEST) -cp "$(CP_TEST)" $(TEST_SRCS)
	@echo "junit  run"
	@$(JAVA) -jar $(JU_JAR) execute \
	  --class-path "$(OUT_TEST):$(OUT_MAIN):$(RES_MAIN):$(CJ_JAR)" \
	  --scan-class-path \
	  --details=tree \
	  --disable-banner

# --- run --------------------------------------------------------------------
# ARGS lets you pass flags, e.g.  make victim ARGS=--safe-only
victim: build
	@$(JAVA) -cp "$(CP_MAIN)" com.queryshield.victim.VictimApp $(ARGS)

proxy: build
	@$(JAVA) -cp "$(CP_MAIN)" com.queryshield.proxy.ProxyServer $(ARGS)

eval: build
	@$(JAVA) -cp "$(CP_MAIN)" com.queryshield.eval.EvalHarness $(ARGS)

e2e: build
	@bash e2e_test.sh

loadtest: build
	@$(JAVA) -cp "$(CP_MAIN)" com.queryshield.eval.LoadGen $(ARGS)

# --- housekeeping -----------------------------------------------------------
clean:
	@rm -rf out
	@echo "removed out/"

distclean: clean
	@rm -rf $(LIB)
	@echo "removed $(LIB)/"
