
CXX       := clang++
CXXFLAGS  := -std=c++17 -O2 -Wall -Wextra
BUILD_DIR := build
TARGET    := $(BUILD_DIR)/jvm_profiler
SRC       := jvm_profiler.cpp

.PHONY: build run clean

build: $(TARGET)

$(TARGET): $(SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

run: build
	./$(TARGET) --interval-ms 1000 --jvm-summary-secs 15 --vmmap-summary-secs 30

clean:
	rm -rf $(BUILD_DIR)
	rm -rf tmp
