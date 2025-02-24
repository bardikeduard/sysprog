#include "parser.h"
#include "bg_array.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#define container_of(ptr, type, member) (type*)((char*)(ptr) - offsetof(type, member))

struct exec_result {
	int need_exit;
	int return_code;

	pid_t *bg_pids;
	size_t bg_count;
};

static struct exec_result
make_result(int need_exit, int return_code, pid_t *bg_pids, size_t bg_count)
{
	struct exec_result res;
	res.need_exit = need_exit;
	res.return_code = return_code;
	res.bg_pids = bg_pids;
	res.bg_count = bg_count;
	return res;
}

static int
handle_cd_command(const struct expr *expression)
{
	assert(expression != NULL);

	if (expression->cmd.arg_count != 1) {
		return 1;
	}

	const char *target_path = expression->cmd.args[0];
	if (target_path == NULL) {
		return 1;
	}

	return chdir(target_path);
}

static void
execute_cmd(const struct expr *expression)
{
	assert(expression != NULL);

	char **args = calloc(expression->cmd.arg_count + 2, sizeof(char *));
	args[0] = expression->cmd.exe;
	memcpy(args + 1, expression->cmd.args, sizeof(char *) * expression->cmd.arg_count);
	execvp(expression->cmd.exe, args);
}

static int
wait_children_and_free(pid_t *children, size_t children_count)
{
	assert(children != NULL);

	int last_exitcode = 0;

	for (size_t child_idx = 0; child_idx < children_count; ++child_idx) {
		int status;
		waitpid(children[child_idx], &status, 0);

		if (WIFEXITED(status)) {
			last_exitcode = WEXITSTATUS(status);
		}
	}
	free(children);

	return last_exitcode;
}

static void
close_pipes(int *pipes_fds, size_t size)
{
	assert(pipes_fds != NULL);

	for (size_t fd_idx = 0; fd_idx < size; ++fd_idx) {
		close(pipes_fds[fd_idx]);
	}
}

static int
create_pipes(int **pipes_fds, size_t cmd_count)
{
	assert(pipes_fds != NULL);

	int *new_pipes_fds = calloc(2 * cmd_count, sizeof(int));
	if (new_pipes_fds == NULL) {
		return 1;
	}

	for (size_t i = 0; i < cmd_count - 1; ++i) {
		if (pipe(new_pipes_fds + 2 * i + 1) != 0) {
			close_pipes(new_pipes_fds + 1, i);
			free(new_pipes_fds);
			return 1;
		}

		int tmp = new_pipes_fds[2 * i + 1];
		new_pipes_fds[2 * i + 1] = new_pipes_fds[2 * (i + 1)];
		new_pipes_fds[2 * (i + 1)] = tmp;
	}

	*pipes_fds = new_pipes_fds;
	return 0;
}

static struct exec_result
execute_pipeline(struct expr *pipeline_start, size_t cmd_count,
	const char *out_file, enum output_type out_type, int need_wait)
{
	assert(pipeline_start != NULL);

	size_t child_size = 0;
	pid_t *children_pids = calloc(cmd_count, sizeof(pid_t));
	if (children_pids == NULL) {
		puts("calloc error\n");
		return make_result(0, 1, NULL, 0);
	}

	int *pipes_fds;
	if (create_pipes(&pipes_fds, cmd_count) != 0) {
		puts("pipe creation error\n");
		free(children_pids);
		return make_result(0, 1, NULL, 0);
	}

	pipes_fds[0] = STDIN_FILENO;
	pipes_fds[2 * cmd_count - 1] = STDOUT_FILENO;

	struct expr *expression = pipeline_start;
	size_t i = 0;

	while (i < cmd_count) {
		if (expression->type != EXPR_TYPE_COMMAND) {
			expression = expression->next;
			continue;
		}

		if (strcmp("cd", expression->cmd.exe) == 0) {
			if (cmd_count == 1 && handle_cd_command(expression) != 0) {
				puts("cd error\n");

				close_pipes(pipes_fds, 2 * (cmd_count - 1));
				free(pipes_fds);
				free(children_pids);

				return make_result(0, -1, NULL, 0);
			}
		}
		else if (strcmp("exit", expression->cmd.exe) == 0) {
			if (i == cmd_count - 1) {
				close_pipes(pipes_fds + 1, 2 * (cmd_count - 1));
				free(pipes_fds);
				wait_children_and_free(children_pids, child_size);

				if (expression->cmd.arg_count != 0) {
					char *end;
					int return_code = (int) strtol(expression->cmd.args[0], &end, 10);
					return make_result(cmd_count == 1, return_code, NULL, 0);
				}

				return make_result(cmd_count == 1, 0, NULL, 0);
			}
		}
		else {
			pid_t child_pid = fork();
			switch (child_pid) {
				case -1: {
					puts("fork error\n");
					close_pipes(pipes_fds + 1, 2 * (cmd_count - 1));
					free(pipes_fds);
					wait_children_and_free(children_pids, child_size);

					return make_result(1, 1, children_pids, child_size);
				}

				case 0: {
					free(children_pids);

					for (size_t fd_idx = 1; fd_idx < 2 * cmd_count - 1; ++fd_idx) {
						if (fd_idx != 2 * i + 1 && fd_idx != 2 * i) {
							close(pipes_fds[fd_idx]);
						}
					}

					if (need_wait != 0 || i != 0) {
						if (dup2(pipes_fds[2 * i], STDIN_FILENO) != STDIN_FILENO) {
							puts("dup2 error\n");

							close(pipes_fds[2 * i]);
							close(pipes_fds[2 * i + 1]);
							free(pipes_fds);

							return make_result(1, 0, NULL, 0);
						}
					}
					else {
						close(STDIN_FILENO);
					}

					int out_fd = pipes_fds[2 * i + 1];
					if (out_type != OUTPUT_TYPE_STDOUT && out_file != NULL && i == cmd_count - 1) {
						out_fd = open(out_file,
							O_CREAT | O_WRONLY | (out_type == OUTPUT_TYPE_FILE_NEW ? O_TRUNC : O_APPEND),
							S_IRWXU | S_IRWXG | S_IRWXO
						);
						if (out_fd == -1) {
							puts("out file open error\n");

							close(pipes_fds[2 * i]);
							close(pipes_fds[2 * i + 1]);
							free(pipes_fds);

							return make_result(1, 0, NULL, 0);
						}
					}

					if (dup2(out_fd, STDOUT_FILENO) != STDOUT_FILENO) {
						puts("dup2 error\n");

						close(pipes_fds[2 * i]);
						close(pipes_fds[2 * i + 1]);
						free(pipes_fds);

						return make_result(1, 0, NULL, 0);
					}

					free(pipes_fds);

					execute_cmd(expression);
					return make_result(1, 0, NULL, 0);
				}

				default: {
					children_pids[child_size++] = child_pid;
					break;
				}
			}
		}

		expression = expression->next;
		++i;
	}

	close_pipes(pipes_fds + 1, 2 * (cmd_count - 1));
	free(pipes_fds);

	if (need_wait) {
		return make_result(0, wait_children_and_free(children_pids, child_size), NULL, 0);
	}

	return make_result(0, 0, children_pids, child_size);
}

static struct exec_result
execute_logical_operand(struct expr *start, const char *out_file,
	enum output_type out_type, int need_wait)
{
	assert(start != NULL);

	size_t cmd_count = 0;
	struct expr *iter = start;

	while (iter != NULL) {
		switch (iter->type) {
		case EXPR_TYPE_AND:
		case EXPR_TYPE_OR: {
			return execute_pipeline(start, cmd_count, out_file, out_type, need_wait);
		}

		case EXPR_TYPE_COMMAND: {
			++cmd_count;
			break;
		}

		default: {
			break;
		}
		}

		iter = iter->next;
	}

	return execute_pipeline(start, cmd_count, out_file, out_type, need_wait);
}

static int
is_expr_logical(const struct expr *e)
{
	assert(e != NULL);
	return e->type == EXPR_TYPE_AND || e->type == EXPR_TYPE_OR;
}

static struct exec_result
execute_command_line(const struct command_line *line)
{
	assert(line != NULL);

	struct expr *iter = line->head;
	struct expr *operand_start = iter;
	while (iter != NULL && !is_expr_logical(iter)) {
		iter = iter->next;
	}

	int is_last = (iter == NULL);
	struct exec_result prev_result = execute_logical_operand(operand_start,
		is_last ? line->out_file : NULL,
		is_last ? line->out_type : OUTPUT_TYPE_STDOUT,
		is_last ? (line->is_background == 0) : 1
	);
	if (prev_result.need_exit) {
		return prev_result;
	}

	while (iter != NULL) {
		enum expr_type op = iter->type;
		iter = iter->next;

		if ((op == EXPR_TYPE_AND && prev_result.return_code == 0) ||
			(op == EXPR_TYPE_OR && prev_result.return_code != 0)) {
			operand_start = iter;

			while (iter != NULL && !is_expr_logical(iter)) {
				iter = iter->next;
			}

			is_last = (iter == NULL);
			prev_result = execute_logical_operand(operand_start,
				is_last ? line->out_file : NULL,
				is_last ? line->out_type : OUTPUT_TYPE_STDOUT,
				is_last ? (line->is_background == 0) : 1
			);
			if (prev_result.need_exit) {
				return prev_result;
			}
		}
	}

	return prev_result;
}

int
main(void)
{
	const size_t buf_size = 1024;
	char buf[buf_size];
	ssize_t rc;
	struct parser *p = parser_new();
	int last_retcode = 0;

	struct bg_array bg_proc;
	bg_array_init(&bg_proc);

	while ((rc = read(STDIN_FILENO, buf, buf_size)) > 0) {
		parser_feed(p, buf, rc);
		struct command_line *line = NULL;
		while (true) {
			enum parser_error err = parser_pop_next(p, &line);
			if (err == PARSER_ERR_NONE && line == NULL)
				break;
			if (err != PARSER_ERR_NONE) {
				printf("Error: %d\n", (int)err);
				continue;
			}

			struct exec_result result = execute_command_line(line);
			last_retcode = result.return_code;
			command_line_delete(line);

			if (result.bg_pids != NULL) {
				for (size_t i = 0; i < result.bg_count; ++i) {
					bg_array_push(&bg_proc, result.bg_pids[i]);
				}

				free(result.bg_pids);
			}

			bg_array_wait_nonblock(&bg_proc);

			if (result.need_exit != 0) {
				bg_array_free(&bg_proc);
				parser_delete(p);
				return result.return_code;
			}
		}
	}

	bg_array_free(&bg_proc);
	parser_delete(p);
	return last_retcode;
}
