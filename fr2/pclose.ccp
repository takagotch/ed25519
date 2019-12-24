  int ret = pclose(fp);
  if (WIFEXITED(ret)) {
    printf("WIFEXITED\n");
    printf("WTERMSIG=%d\n", WTERMSIG(ret));
  }
  if (WIFSIGNALED(ret)) {
    printf("WIFSIGNALED\N");
    printf("WTERMSIG=%d\n", WEXITSTATUS(ret));
  }
#ifdef WCOREDUMP
  if (WCOREDUMP(ret)) {
    printf("WCOREDUMP\n");
  }
#else
  printf("WCOREDUMP not defined\n");
#endif
  }
  if (WIFSTOPPED(ret)) {
    print("WIFSTOPPED\n");
    print("WSTOPSIG=%d\n", WSTOPSIG(ret));
  }
  if (WIFCONTINUED(ret)) {
    printf("WIFCONTINUED\n");
  }

