package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type flagSection struct {
	title string
	flags []string
}

var flagSections = []flagSection{
	{
		title: "Essential",
		flags: []string{"verbose", "json", "sarif", "dashboard", "profile", "fail-on", "color", "benchmark", "runs", "help", "version"},
	},
	{
		title: "Git & CI",
		flags: []string{"diff", "diff-base", "staged", "history", "annotations", "baseline", "update-baseline", "suppress"},
	},
	{
		title: "Filtering",
		flags: []string{"min-severity", "min-confidence", "tag", "include-tests"},
	},
	{
		title: "Policy & rules",
		flags: []string{"rules", "policy", "policy-dir", "profiles", "config"},
	},
	{
		title: "Watch mode",
		flags: []string{"watch", "watch-interval"},
	},
	{
		title: "Performance (rarely needed)",
		flags: []string{"workers", "max-files", "memory-limit-mb", "max-file-size-mb", "max-concurrent-reads"},
	},
}

func renderGroupedHelp(cmd *cobra.Command) string {
	var b strings.Builder

	b.WriteString(cmd.Long + "\n\n")

	if usage := cmd.UseLine(); usage != "" {
		b.WriteString("Usage:\n  " + usage + "\n")
	}

	if cmds := visibleSubcommands(cmd); len(cmds) > 0 {
		b.WriteString("\nAvailable commands:\n")
		for _, sub := range cmds {
			b.WriteString(fmt.Sprintf("  %-18s %s\n", sub.Name(), firstLine(sub.Short)))
		}
	}

	b.WriteString("\nFlags:\n")
	covered := map[string]bool{}
	for _, section := range flagSections {
		body := renderFlagSection(cmd, section.flags)
		if body == "" {
			continue
		}
		for _, name := range section.flags {
			covered[name] = true
		}
		b.WriteString(fmt.Sprintf("  %s\n%s\n", titleStyle(section.title), indent(body, 4)))
	}
	if leftover := renderUncoveredFlags(cmd, covered); leftover != "" {
		b.WriteString(indent(leftover, 4) + "\n")
	}

	if c := cmd.Commands(); len(c) > 0 {
		b.WriteString("\nUse \"minesweep <command> --help\" for more information about a command.\n")
	}
	b.WriteString("\nDocumentation: https://github.com/minesweep/minesweep#readme\n")

	return b.String()
}

func renderFlagSection(cmd *cobra.Command, names []string) string {
	fs := pflag.NewFlagSet("section", pflag.ContinueOnError)
	fs.SortFlags = false
	added := false
	for _, name := range names {
		if f := cmd.Flags().Lookup(name); f != nil {
			fs.AddFlag(f)
			added = true
		}
	}
	if !added {
		return ""
	}
	return strings.TrimRight(fs.FlagUsagesWrapped(0), "\n")
}

func renderUncoveredFlags(cmd *cobra.Command, covered map[string]bool) string {
	fs := pflag.NewFlagSet("other", pflag.ContinueOnError)
	fs.SortFlags = false
	cmd.NonInheritedFlags().VisitAll(func(f *pflag.Flag) {
		if !covered[f.Name] && f.Name != "help" {
			fs.AddFlag(f)
		}
	})
	return strings.TrimRight(fs.FlagUsagesWrapped(0), "\n")
}

func visibleSubcommands(cmd *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, sub := range cmd.Commands() {
		if sub.Name() == "help" || sub.Name() == "completion" {
			continue
		}
		if !sub.Hidden {
			out = append(out, sub)
		}
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func titleStyle(s string) string {
	return s + ":"
}

func indent(s string, padSpaces int) string {
	pad := strings.Repeat(" ", padSpaces)
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}
