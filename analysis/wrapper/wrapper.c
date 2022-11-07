#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

char ** get_new_argv_gdb_batch(int argc, char *argv[], int *ret_argc){
  int i;
  int gdb_argc = 5;
  int new_argc = argc + gdb_argc;

  char ** new_argv = (char**) malloc(new_argc * sizeof(char*) + sizeof(char*));
  new_argv[0] = "/usr/bin/gdb";
  new_argv[1] = "-batch";
  new_argv[2] = "-x";
  new_argv[3] = "~/projects/pirop-code/analysis/gdb_scripts/gather_stack_traces.gdb";
  new_argv[4] = "--args";
  for(i = 0; i < argc; i++){
    new_argv[gdb_argc+i] = argv[i];
  }
  new_argv[new_argc] = NULL;

  *ret_argc = new_argc;
  return new_argv;
}

char ** get_new_argv_gdb(int argc, char *argv[], int *ret_argc){
  int i;
  int gdb_argc = 4;
  int new_argc = argc + gdb_argc;

  char ** new_argv = (char**) malloc(new_argc * sizeof(char*) + sizeof(char*));
  new_argv[0] = "/usr/bin/gdb";
  new_argv[1] = "-x";
  new_argv[2] = "~/projects/pirop-code/analysis/gdb_scripts/gather_stack_traces.gdb";
  new_argv[3] = "--args";
  for(i = 0; i < argc; i++){
    new_argv[gdb_argc+i] = argv[i];
  }
  new_argv[new_argc] = NULL;

  *ret_argc = new_argc;
  return new_argv;
}

char * get_orig_app_path(char *wrapper_app_path){
  size_t path_len = strlen(wrapper_app_path);
  char * original_app = (char*) malloc(strlen(wrapper_app_path) + strlen(".orig") + 1);
  memcpy(original_app, wrapper_app_path, path_len);
  memcpy(original_app+path_len, ".orig", strlen(".orig"));
  original_app[path_len + strlen(".orig")] = '\0';
  return original_app;
}

int dump_old_new_argv(int argc, char *argv[], int new_argc, char **new_argv){
  int i;
  FILE *fp = fopen("execve.txt", "a");
  if(!fp){
    fprintf(stderr, "Could not open file..\n");
    return 1;
  }

  //fprintf(fp,"== pid : %d / argc : %d / new_argc : %d ==\n", getpid(), argc, new_argc);
  //for(i = 0; i < argc; i++){
  //  fprintf(fp, "argv[%d] = %s\n", i, argv[i]);
  //}
  fprintf(fp, "[$] ");
  for(i = 0; i < argc; i++){
    fprintf(fp, "%s ", argv[i]);
  }
  fprintf(fp, "\n");

  //for(i = 0; i < new_argc; i++){
  //  fprintf(fp, "new_argv[%d] = %s\n", i, new_argv[i]);
  //}
  fprintf(fp, "[$] ");
  for(i = 0; i < new_argc; i++){
    fprintf(fp, "%s ", new_argv[i]);
  }
  fprintf(fp,"\n\n");

  if(fclose(fp)){
    fprintf(stderr, "Could not close file..\n");
    return 1;
  }

  return 0;
}

int main (int argc, char *argv[])
{
  int i;
  argv[0] = get_orig_app_path(argv[0]);

#if 1
  int new_argc;
  char **new_argv = get_new_argv_gdb_batch(argc, argv, &new_argc);
#else
  int new_argc = argc;
  char **new_argv = argv;
#endif
  
  if(dump_old_new_argv(argc, argv, new_argc, new_argv)){
    fprintf(stderr, "Could not dump old and new argv..\n");
    return 1;
  }

  execv(new_argv[0], new_argv);
  return 0;
}

