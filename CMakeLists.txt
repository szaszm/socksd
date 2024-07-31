cmake_minimum_required(VERSION 3.20)
project(socksd VERSION 0.2 LANGUAGES C)

add_executable(socksd src/main.c src/Logger.c src/Client.c)
target_include_directories(socksd PRIVATE src)
target_compile_options(socksd PRIVATE
	$<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>,$<C_COMPILER_ID:GNU>>:
		-Wall -Wextra -Wpedantic -Walloca -Wcast-qual -Wconversion -Wdate-time>
	$<$<C_COMPILER_ID:GNU>:
		-Wformat-overflow -Wnull-dereference -Wimplicit-fallthrough=5 -Wmissing-include-dirs
		-Wswitch-enum -Wstrict-aliasing=1 -Wduplicated-branches -Wduplicated-cond -Wshadow -Wundef -Wlogical-op -Wmissing-declarations -Wredundant-decls>
	$<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>>:
		-Wabstract-vbase-init -Wanon-enum-enum-conversion -Wassign-enum -Watomic-implicit-seq-cst
		-Wbad-function-cast -Wbitfield-constant-conversion -Wc++11-narrowing -Wchar-subscripts
		-Wcomma -Wctad-maybe-unsupported -Wdeprecated -Wduplicate-enum -Wfor-loop-analysis -Wformat-type-confusion
		-Wfour-char-constants -Wframe-address -Wgnu -Wheader-hygiene -Widiomatic-parentheses -Wint-in-bool-context
		-Wmicrosoft -Wmost>)
