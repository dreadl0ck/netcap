# bash completion for NETCAP
# on macOS: add to /usr/local/etc/bash_completion.d/ then . /usr/local/etc/bash_completion.d/net
# on Linux: add to /etc/bash_completion.d/ then . /etc/bash_completion.d/net

_net()
{
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

	opts=$(net -previous=${prev} -current=${cur} -full="\"${COMP_WORDS[*]}\"")

	COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
	return 0
} &&
complete -F _net net