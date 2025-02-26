#include "parser.h"
#include "bg_array.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

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
is_expr_logical(const struct expr *e)
{
	assert(e != NULL);
	return e->type == EXPR_TYPE_AND || e->type == EXPR_TYPE_OR;
}

static int is_expr_logical_last(const struct expr *e)
{
	assert(e != NULL);
	return e->next == NULL || is_expr_logical(e->next);
}

static struct exec_result
execute_pipeline(struct expr *pipeline_start,
	const char *out_file, enum output_type out_type, int need_wait)
{
	assert(pipeline_start != NULL);

	struct pid_array children_pids;
	if (pid_array_init(&children_pids) != 0) {
		dprintf(STDERR_FILENO, "calloc error\n");
		return make_result(0, 1, NULL, 0);
	}

	size_t i = 0;
	int pipe_fds[3] = {STDIN_FILENO, STDOUT_FILENO, -1};
	struct expr *expression = pipeline_start;

	while (expression != NULL && !is_expr_logical(expression)) {
		if (expression->type != EXPR_TYPE_COMMAND) {
			expression = expression->next;
			continue;
		}

		if (!is_expr_logical_last(expression)) {
			if (pipe(pipe_fds + 1) != 0) {
				dprintf(STDERR_FILENO, "pipe creation error %zu\n", i);
				return make_result(0, 0, NULL, 0);
			}

			int tmp = pipe_fds[1];
			pipe_fds[1] = pipe_fds[2];
			pipe_fds[2] = tmp;
		}

		if (strcmp("cd", expression->cmd.exe) == 0 && children_pids.pa_size == 0 && is_expr_logical_last(expression)) {
			if (handle_cd_command(expression) != 0) {
				dprintf(STDERR_FILENO, "cd error\n");
				pid_array_free(&children_pids);

				if (pipe_fds[0] != STDIN_FILENO) {
					close(pipe_fds[0]);
				}

				if (pipe_fds[1] != STDOUT_FILENO) {
					close(pipe_fds[1]);
				}

				return make_result(0, -1, NULL, 0);
			}
		}
		else if (strcmp("exit", expression->cmd.exe) == 0) {
			if (expression->next == NULL || is_expr_logical(expression->next)) {
				int is_one_cmd = (children_pids.pa_size == 0);
				pid_array_wait_and_free(&children_pids);

				if (pipe_fds[0] != STDIN_FILENO) {
					close(pipe_fds[0]);
				}

				if (pipe_fds[1] != STDOUT_FILENO) {
					close(pipe_fds[1]);
				}

				if (expression->cmd.arg_count != 0) {
					char *end;
					int return_code = (int) strtol(expression->cmd.args[0], &end, 10);
					return make_result(is_one_cmd, return_code, NULL, 0);
				}

				return make_result(is_one_cmd, 0, NULL, 0);
			}
		}
		else {
			pid_t child_pid = fork();

			if (child_pid == -1) {
				dprintf(STDERR_FILENO, "fork error\n");
				pid_array_wait_and_free(&children_pids);

				return make_result(1, 1, NULL, 0);
			}

			if (child_pid == 0) {
				pid_array_free(&children_pids);

				if (need_wait != 0 || children_pids.pa_size > 0) {
					if (dup2(pipe_fds[0], STDIN_FILENO) != STDIN_FILENO) {
						dprintf(STDERR_FILENO, "dup2 error\n");
						return make_result(1, 0, NULL, 0);
					}
				}
				else {
					close(pipe_fds[0]);
				}

				int out_fd = pipe_fds[1];
				if (is_expr_logical_last(expression)) {
					if (out_fd != STDOUT_FILENO) {
						close(out_fd);
					}

					if (out_type != OUTPUT_TYPE_STDOUT) {
						out_fd = open(out_file,
							O_CREAT | O_WRONLY | (out_type == OUTPUT_TYPE_FILE_NEW ? O_TRUNC : O_APPEND),
							S_IRWXU | S_IRWXG | S_IRWXO
						);
						if (out_fd == -1) {
							dprintf(STDERR_FILENO, "out file open error\n");
							return make_result(1, 0, NULL, 0);
						}
					}
					else {
						out_fd = STDOUT_FILENO;
					}
				}

				if (dup2(out_fd, STDOUT_FILENO) != STDOUT_FILENO) {
					dprintf(STDERR_FILENO, "dup2 error\n");
					return make_result(1, 0, NULL, 0);
				}

				if (pipe_fds[2] != -1) {
					close(pipe_fds[2]);
				}

				execute_cmd(expression);
				return make_result(1, 0, NULL, 0);
			}

			if (pid_array_push(&children_pids, child_pid) != 0) {
				dprintf(STDERR_FILENO, "pid_array_push error\n");
				break;
			}
		}

		if (pipe_fds[0] != STDIN_FILENO) {
			close(pipe_fds[0]);
		}

		if (pipe_fds[1] != STDOUT_FILENO) {
			close(pipe_fds[1]);
		}

		pipe_fds[0] = pipe_fds[2];
		expression = expression->next;
	}

	if (pipe_fds[0] != STDIN_FILENO) {
		close(pipe_fds[0]);
	}

	if (need_wait) {
		return make_result(0, pid_array_wait_and_free(&children_pids), NULL, 0);
	}

	return make_result(0, 0, children_pids.pa_children, children_pids.pa_size);
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
	struct exec_result prev_result = execute_pipeline(operand_start,
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
			prev_result = execute_pipeline(operand_start,
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

	struct pid_array bg_proc;
	if (pid_array_init(&bg_proc) != 0) {
		dprintf(STDERR_FILENO, "init error\n");
		parser_delete(p);
		return 1;
	}

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
					if (pid_array_push(&bg_proc, result.bg_pids[i]) != 0) {
						dprintf(STDERR_FILENO, "bg_array_push error\n");
						break;
					}
				}

				free(result.bg_pids);
			}

			if (pid_array_wait_nonblock(&bg_proc) != 0) {
				dprintf(STDERR_FILENO, "bg_array_wait_nonblock error\n");
			}

			if (result.need_exit != 0) {
				pid_array_free(&bg_proc);
				parser_delete(p);
				return result.return_code;
			}
		}
	}

	pid_array_free(&bg_proc);
	parser_delete(p);
	return last_retcode;
}
