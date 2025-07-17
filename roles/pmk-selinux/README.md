# SELinux policies

This is an ansible port of the https://github.com/platform9/selinuxmodules upstream repository.  We include a single
SELinux policy for the pf9 agent in here.  There are other policies which may/may not be useful for different storage
and networking configurations in the upstream repostiory above.  Please use the upstream repository for ongoing R&D into
various policy configurations, and when your sure they belong in PMK or PMO, duplicate those files into the "files"
directory of this task.