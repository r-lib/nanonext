## R CMD check results

0 errors | 0 warnings | 0 notes

This submission fixes the warning from the GCC-ASAN machine. It is a known false positive arising from the use of LTO on that machine. We prevent inlining by the compiler for those specific cases.
