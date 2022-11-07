# Setting up the gdb scripts

First setup peda: https://github.com/longld/peda

Then set up the scripts, by putting the paths in ~/.gdbinit
```
$ echo "source `pwd`/find_gadgets.py" >> ~/.gdbinit
$ echo "source `pwd`/find_interesting_calls.py" >> ~/.gdbinit
$ echo "source `pwd`/gather_stack_traces.py" >> ~/.gdbinit
```

Or, the scripts can also be put in the following directory:
```
/usr/share/gdb/python/gdb
```
