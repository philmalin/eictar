# Bash completion for eictar(1).
#
# Load it in the current shell:
#   source completions/eictar.bash
# Or load it in each new shell, with the bash-completion package:
#   cp completions/eictar.bash ~/.local/share/bash-completion/completions/eictar
# Or without that package, add the source line to ~/.bashrc.
#
# It completes the options, the values of the options that take a fixed set
# of values, a directory or a file, and file names. -f completes directories
# and .ect files. It needs bash 3.2 or later, and no other package.
#
# src/internal/cli/completion_test.go keeps the lists in step with the parser.

# The lists have one word on each line: _eictar sets IFS to a newline, so
# that a file name with a space stays one word.
_eictar_long='--create
--append
--list
--extract
--update
--delete
--compact
--verify
--diff
--diff-extract
--repair
--info
--list-codecs
--change-passphrase
--file
--directory
--destination
--compress
--gzip
--xz
--zstd
--encrypt
--encrypt-index
--passphrase-file
--passphrase-env
--new-passphrase-file
--new-passphrase-env
--kdf-time
--kdf-memory
--kdf-threads
--workers
--chunk-size
--memory-limit
--spill-threshold
--files-from
--exclude
--exclude-from
--regex
--exclude-regex
--dereference
--one-file-system
--no-dedup
--preserve-permissions
--preserve-owner
--preserve-devices
--no-xattrs
--no-acls
--no-owner
--keep-existing
--overwrite
--newer-only
--to-stdout
--strip-components
--scratch-dir
--update-mode
--on-conflict
--keep-going
--dry-run
--long
--json
--quick
--recompress
--verbose
--quiet
--progress
--config
--no-config
--show-config
--version
--help'

_eictar_short='-c
-r
-t
-x
-u
-f
-C
-d
-Z
-z
-J
-e
-j
-T
-X
-R
-h
-p
-k
-O
-n
-v
-q'

_eictar_codecs='flate
gzip
none
s2
xz
zstd'

_eictar_update_modes='newer
different
digest'

_eictar_conflicts='replace
skip
error'

_eictar() {
	local IFS=$'\n'
	local cur=${COMP_WORDS[COMP_CWORD]} prev=
	if ((COMP_CWORD > 0)); then
		prev=${COMP_WORDS[COMP_CWORD - 1]}
	fi
	# bash splits --file=NAME into --file, = and NAME, because = is in
	# COMP_WORDBREAKS.
	if [[ $cur == = ]]; then
		cur=
	elif [[ $prev == = ]] && ((COMP_CWORD > 1)); then
		prev=${COMP_WORDS[COMP_CWORD - 2]}
	fi
	# In a bundle of short options, such as -cf, the last one takes the value.
	if [[ $prev == -[!-]?* ]]; then
		prev=-${prev: -1}
	fi

	COMPREPLY=()
	case $prev in
	-f | --file)
		COMPREPLY=($(compgen -d -- "$cur") $(compgen -f -X '!*.ect' -- "$cur"))
		return
		;;
	-C | --directory | -d | --destination | --scratch-dir)
		COMPREPLY=($(compgen -d -- "$cur"))
		return
		;;
	-T | --files-from | -X | --exclude-from | --passphrase-file | --new-passphrase-file | --config)
		COMPREPLY=($(compgen -f -- "$cur"))
		return
		;;
	--passphrase-env | --new-passphrase-env)
		COMPREPLY=($(compgen -e -- "$cur"))
		return
		;;
	-Z | --compress | --recompress)
		COMPREPLY=($(compgen -W "$_eictar_codecs" -- "$cur"))
		return
		;;
	--update-mode)
		COMPREPLY=($(compgen -W "$_eictar_update_modes" -- "$cur"))
		return
		;;
	--on-conflict)
		COMPREPLY=($(compgen -W "$_eictar_conflicts" -- "$cur"))
		return
		;;
	-j | --workers | --kdf-time | --kdf-memory | --kdf-threads | --chunk-size | --memory-limit | --spill-threshold | --strip-components | --exclude | -R | --regex | --exclude-regex)
		# A number, a size, a glob or a regular expression: nothing to offer.
		return
		;;
	esac

	case $cur in
	--*) COMPREPLY=($(compgen -W "$_eictar_long" -- "$cur")) ;;
	-*) COMPREPLY=($(compgen -W "$_eictar_short"$'\n'"$_eictar_long" -- "$cur")) ;;
	*) COMPREPLY=($(compgen -f -- "$cur")) ;;
	esac
}

complete -o filenames -F _eictar eictar
