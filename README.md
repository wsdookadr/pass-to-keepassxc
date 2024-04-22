## Usage

```bash
# move all parentless passwords to the other/ sub-directory
cd ~/.password-store/ ; mkdir other ; ls *.gpg | sed -e 's/\.gpg//' | xargs -I{} pass mv {} other/{}

# perform conversion
./pass-to-keepassxc.py ~/.password-store/ > import-keepassxc.xml
openssl rand -out keyfile.keyx 256
keepassxc-cli import --set-key-file keyfile.keyx import-keepassxc.xml keepass-keystore.kbdx

# list entries to double-check that all have been converted
keepassxc-cli ls -R --no-password -k keyfile.keyx keepass-keystore.kbdx

# display multiline password entries for manual adjustment
cat entries-multiline.txt
```

## Versions tested

- KeePassXC 2.7.4
- Python 3.11.2
- lxml 5.2.1
- pass 1.7.4
- GnuPG 2.2.40
- Debian 12
