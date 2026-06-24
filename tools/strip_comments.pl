#!/usr/bin/perl
#
# Strip non-license comments from a C source/header file (stdin -> stdout).
#
# Used by tools/update_nng.sh when vendoring NNG: the bundled tree carries only
# the leading // license header, not NNG's inline commentary, which keeps the
# vendored sources lean and the diff against a fresh upstream checkout focused on
# real code.
#
# Behaviour:
#   * Preserves the leading // license header verbatim (after any leading blank
#     lines, e.g. core/log.c), so copyright / license notices are never lost.
#   * Removes every other // and /* */ comment, honouring string and char
#     literals so a // or /* inside a literal is left intact.
#   * Deletes lines that consist solely of a comment, keeps original blank lines,
#     and squeezes runs of blank lines to a single blank.

use strict;
use warnings;

my @lines = <STDIN>;
chomp @lines;

# Capture leading blank lines + the contiguous // license header verbatim.
my @header;
{
    my $i = 0;
    $i++ while $i < @lines && $lines[$i] =~ /^\s*$/;
    if ($i < @lines && $lines[$i] =~ m{^\s*//}) {
        $i++ while $i < @lines && $lines[$i] =~ m{^\s*//};
        @header = splice(@lines, 0, $i);
    }
}

my $in_block = 0;
my @out;
for my $line (@lines) {
    my $orig_blank = ($line =~ /^\s*$/);
    my $res = '';
    my $i   = 0;
    my $n   = length $line;
    while ($i < $n) {
        my $c  = substr($line, $i, 1);
        my $c2 = ($i + 1 < $n) ? substr($line, $i, 2) : '';
        if ($in_block) {
            if ($c2 eq '*/') { $in_block = 0; $i += 2; } else { $i += 1; }
            next;
        }
        if ($c eq '"' || $c eq "'") {           # string / char literal
            my $q = $c; $res .= $c; $i++;
            while ($i < $n) {
                my $s = substr($line, $i, 1); $res .= $s; $i++;
                last if $s eq $q;
                if ($s eq '\\' && $i < $n) { $res .= substr($line, $i, 1); $i++; }
            }
            next;
        }
        if ($c2 eq '//') { last; }               # line comment -> drop to EOL
        if ($c2 eq '/*') { $in_block = 1; $i += 2; next; }
        $res .= $c; $i++;
    }
    $res =~ s/\s+$//;                             # right-trim
    if    ($orig_blank) { push @out, ''; }        # keep original blank
    elsif ($res ne '')  { push @out, $res; }      # code (comment removed)
    # else: comment-only line -> delete entirely
}

my @sq; my $prev_blank = 0;
for my $l (@out) {
    my $blank = ($l eq '');
    next if $blank && $prev_blank;
    push @sq, $l; $prev_blank = $blank;
}
print "$_\n" for @header;
print "$_\n" for @sq;
