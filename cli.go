package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rob121/cannon/extension"
)

func bansTableName() string {
	return extension.TableName(extension.TablePrefixFromName(extensionName), "bans")
}

func runCLI(cmd string, args []string) error {
	switch cmd {
	case "list-bans":
		return cliListBans(args)
	case "unban":
		return cliUnban(args)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func ensureSiteFlag(site string) {
	site = strings.TrimSpace(site)
	if site == "" {
		return
	}
	for _, a := range os.Args {
		if strings.HasPrefix(a, "--site=") {
			return
		}
	}
	// OpenDB only recognizes --site=; accept "--site value" from flag parsing.
	os.Args = append(os.Args, "--site="+site)
}

func cliListBans(args []string) error {
	fs := flag.NewFlagSet("list-bans", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	site := fs.String("site", "", "Cannon site id (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*site) == "" {
		return fmt.Errorf("list-bans: --site is required")
	}
	ensureSiteFlag(*site)
	db, _, err := extension.OpenDB()
	if err != nil {
		return err
	}
	table := bansTableName()
	var rows []banRow
	err = db.Table(table).
		Where("expires_at > ?", time.Now().UTC()).
		Order("expires_at asc").
		Find(&rows).Error
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("No active bans.")
		return nil
	}
	for _, row := range rows {
		fmt.Printf("%s\texpires %s\t%s\n", row.IP, row.ExpiresAt.UTC().Format(time.RFC3339), strings.TrimSpace(row.Reason))
	}
	return nil
}

func cliUnban(args []string) error {
	fs := flag.NewFlagSet("unban", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	site := fs.String("site", "", "Cannon site id (required)")
	ip := fs.String("ip", "", "Client IP to unban")
	all := fs.Bool("all", false, "Remove all bans for the site")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*site) == "" {
		return fmt.Errorf("unban: --site is required")
	}
	*ip = strings.TrimSpace(*ip)
	if !*all && *ip == "" {
		return fmt.Errorf("unban: provide --ip or --all")
	}
	if *all && *ip != "" {
		return fmt.Errorf("unban: use either --ip or --all, not both")
	}
	ensureSiteFlag(*site)
	db, _, err := extension.OpenDB()
	if err != nil {
		return err
	}
	table := bansTableName()
	if *all {
		res := db.Table(table).Where("1 = 1").Delete(&banRow{})
		if res.Error != nil {
			return res.Error
		}
		fmt.Printf("Removed %d ban(s).\n", res.RowsAffected)
		return nil
	}
	res := db.Table(table).Where("ip = ?", *ip).Delete(&banRow{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		fmt.Printf("No ban found for %s.\n", *ip)
		return nil
	}
	fmt.Printf("Unbanned %s.\n", *ip)
	return nil
}
