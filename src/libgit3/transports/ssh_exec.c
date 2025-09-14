/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "ssh_exec.h"

#ifdef GIT3_SSH_EXEC

#include "common.h"

#include "config.h"
#include "net.h"
#include "path.h"
#include "futils.h"
#include "process.h"
#include "transports/smart.h"

typedef struct {
	git3_smart_subtransport_stream parent;
} ssh_exec_subtransport_stream;

typedef struct {
	git3_smart_subtransport parent;
	git3_transport *owner;

	ssh_exec_subtransport_stream *current_stream;

	char *cmd_uploadpack;
	char *cmd_receivepack;

	git3_smart_service_t action;
	git3_process *process;
} ssh_exec_subtransport;

static int ssh_exec_subtransport_stream_read(
	git3_smart_subtransport_stream *s,
	char *buffer,
	size_t buf_size,
	size_t *bytes_read)
{
	ssh_exec_subtransport *transport;
	ssh_exec_subtransport_stream *stream = (ssh_exec_subtransport_stream *)s;
	ssize_t ret;

	GIT3_ASSERT_ARG(stream);
	GIT3_ASSERT(stream->parent.subtransport);

	transport = (ssh_exec_subtransport *)stream->parent.subtransport;

	if ((ret = git3_process_read(transport->process, buffer, buf_size)) < 0) {
		return (int)ret;
	}

	*bytes_read = (size_t)ret;
	return 0;
}

static int ssh_exec_subtransport_stream_write(
        git3_smart_subtransport_stream *s,
        const char *buffer,
        size_t len)
{
	ssh_exec_subtransport *transport;
	ssh_exec_subtransport_stream *stream = (ssh_exec_subtransport_stream *)s;
	ssize_t ret;

	GIT3_ASSERT(stream && stream->parent.subtransport);

	transport = (ssh_exec_subtransport *)stream->parent.subtransport;

	while (len > 0) {
		if ((ret = git3_process_write(transport->process, buffer, len)) < 0)
			return (int)ret;

		len -= ret;
	}

	return 0;
}

static void ssh_exec_subtransport_stream_free(git3_smart_subtransport_stream *s)
{
	ssh_exec_subtransport_stream *stream = (ssh_exec_subtransport_stream *)s;

	git3__free(stream);
}

static int ssh_exec_subtransport_stream_init(
	ssh_exec_subtransport_stream **out,
	ssh_exec_subtransport *transport)
{
	GIT3_ASSERT_ARG(out);

	*out = git3__calloc(sizeof(ssh_exec_subtransport_stream), 1);
	GIT3_ERROR_CHECK_ALLOC(*out);

	(*out)->parent.subtransport = &transport->parent;
	(*out)->parent.read = ssh_exec_subtransport_stream_read;
	(*out)->parent.write = ssh_exec_subtransport_stream_write;
	(*out)->parent.free = ssh_exec_subtransport_stream_free;

	return 0;
}

GIT3_INLINE(int) ensure_transport_state(
	ssh_exec_subtransport *transport,
	git3_smart_service_t expected,
	git3_smart_service_t next)
{
	if (transport->action != expected && transport->action != next) {
		git3_error_set(GIT3_ERROR_NET, "invalid transport state");

		return -1;
	}

	return 0;
}

static int get_ssh_cmdline(
	git3_str *out,
	ssh_exec_subtransport *transport,
	git3_net_url *url,
	const char *command)
{
	git3_remote *remote = ((transport_smart *)transport->owner)->owner;
	git3_repository *repo = remote->repo;
	git3_config *cfg;
	git3_str ssh_cmd = GIT3_STR_INIT;
	const char *default_ssh_cmd = "ssh";
	int error;

	/*
	 * Safety check: like git, we forbid paths that look like an
	 * option as that could lead to injection to ssh that can make
	 * us do unexpected things
	 */
	if (git3_process__is_cmdline_option(url->username)) {
		git3_error_set(GIT3_ERROR_NET, "cannot ssh: username '%s' is ambiguous with command-line option", url->username);
		return -1;
	} else if (git3_process__is_cmdline_option(url->host)) {
		git3_error_set(GIT3_ERROR_NET, "cannot ssh: host '%s' is ambiguous with command-line option", url->host);
		return -1;
	} else if (git3_process__is_cmdline_option(url->path)) {
		git3_error_set(GIT3_ERROR_NET, "cannot ssh: path '%s' is ambiguous with command-line option", url->path);
		return -1;
	}

	if ((error = git3_repository_config_snapshot(&cfg, repo)) < 0)
		return error;

	if ((error = git3__getenv(&ssh_cmd, "GIT3_SSH")) == 0)
		;
	else if (error != GIT3_ENOTFOUND)
		goto done;
	else if ((error = git3_config__get_string_buf(&ssh_cmd, cfg, "core.sshcommand")) < 0 && error != GIT3_ENOTFOUND)
		goto done;

	error = git3_str_printf(out, "%s %s %s \"%s%s%s\" \"%s '%s'\"",
		ssh_cmd.size > 0 ? ssh_cmd.ptr : default_ssh_cmd,
		url->port_specified ? "-p" : "",
		url->port_specified ? url->port : "",
		url->username ? url->username : "",
		url->username ? "@" : "",
		url->host,
		command,
		url->path);

done:
	git3_str_dispose(&ssh_cmd);
	git3_config_free(cfg);
	return error;
}

static int start_ssh(
	ssh_exec_subtransport *transport,
	git3_smart_service_t action,
	const char *sshpath)
{
	const char *env[] = { "GIT3_DIR=" };

	git3_process_options process_opts = GIT3_PROCESS_OPTIONS_INIT;
	git3_net_url url = GIT3_NET_URL_INIT;
	git3_str ssh_cmdline = GIT3_STR_INIT;
	const char *command;
	int error;

	process_opts.capture_in = 1;
	process_opts.capture_out = 1;
	process_opts.capture_err = 0;

	switch (action) {
	case GIT3_SERVICE_UPLOADPACK_LS:
		command = transport->cmd_uploadpack ?
		          transport->cmd_uploadpack : "git-upload-pack";
		break;
	case GIT3_SERVICE_RECEIVEPACK_LS:
		command = transport->cmd_receivepack ?
		          transport->cmd_receivepack : "git-receive-pack";
		break;
	default:
		git3_error_set(GIT3_ERROR_NET, "invalid action");
		error = -1;
		goto done;
	}

	if (git3_net_str_is_url(sshpath))
		error = git3_net_url_parse(&url, sshpath);
	else
		error = git3_net_url_parse_scp(&url, sshpath);

	if (error < 0)
		goto done;

	if ((error = get_ssh_cmdline(&ssh_cmdline, transport, &url, command)) < 0)
		goto done;

	if ((error = git3_process_new_from_cmdline(&transport->process,
	     ssh_cmdline.ptr, env, ARRAY_SIZE(env), &process_opts)) < 0 ||
	    (error = git3_process_start(transport->process)) < 0) {
		git3_process_free(transport->process);
		transport->process = NULL;
		goto done;
	}

done:
	git3_str_dispose(&ssh_cmdline);
	git3_net_url_dispose(&url);
	return error;
}

static int ssh_exec_subtransport_action(
	git3_smart_subtransport_stream **out,
	git3_smart_subtransport *t,
	const char *sshpath,
	git3_smart_service_t action)
{
	ssh_exec_subtransport *transport = (ssh_exec_subtransport *)t;
	ssh_exec_subtransport_stream *stream = NULL;
	git3_smart_service_t expected;
	int error;

	switch (action) {
	case GIT3_SERVICE_UPLOADPACK_LS:
	case GIT3_SERVICE_RECEIVEPACK_LS:
		if ((error = ensure_transport_state(transport, 0, 0)) < 0 ||
		    (error = ssh_exec_subtransport_stream_init(&stream, transport)) < 0 ||
		    (error = start_ssh(transport, action, sshpath)) < 0)
		    goto on_error;

		transport->current_stream = stream;
		break;

	case GIT3_SERVICE_UPLOADPACK:
	case GIT3_SERVICE_RECEIVEPACK:
		expected = (action == GIT3_SERVICE_UPLOADPACK) ?
			GIT3_SERVICE_UPLOADPACK_LS : GIT3_SERVICE_RECEIVEPACK_LS;

		if ((error = ensure_transport_state(transport, expected, action)) < 0)
			goto on_error;

		break;

	default:
		git3_error_set(GIT3_ERROR_INVALID, "invalid service request");
		goto on_error;
	}

	transport->action = action;
	*out = &transport->current_stream->parent;

	return 0;

on_error:
	if (stream != NULL)
		ssh_exec_subtransport_stream_free(&stream->parent);

	return -1;
}

static int ssh_exec_subtransport_close(git3_smart_subtransport *t)
{
	ssh_exec_subtransport *transport = (ssh_exec_subtransport *)t;

	if (transport->process) {
		git3_process_close(transport->process);
		git3_process_free(transport->process);
		transport->process = NULL;
	}

	transport->action = 0;

	return 0;
}

static void ssh_exec_subtransport_free(git3_smart_subtransport *t)
{
	ssh_exec_subtransport *transport = (ssh_exec_subtransport *)t;

	git3__free(transport->cmd_uploadpack);
	git3__free(transport->cmd_receivepack);
	git3__free(transport);
}

int git3_smart_subtransport_ssh_exec(
	git3_smart_subtransport **out,
	git3_transport *owner,
	void *payload)
{
	ssh_exec_subtransport *transport;

	GIT3_UNUSED(payload);

	transport = git3__calloc(sizeof(ssh_exec_subtransport), 1);
	GIT3_ERROR_CHECK_ALLOC(transport);

	transport->owner = owner;
	transport->parent.action = ssh_exec_subtransport_action;
	transport->parent.close = ssh_exec_subtransport_close;
	transport->parent.free = ssh_exec_subtransport_free;

	*out = (git3_smart_subtransport *) transport;
	return 0;
}

int git3_smart_subtransport_ssh_exec_set_paths(
	git3_smart_subtransport *subtransport,
	const char *cmd_uploadpack,
	const char *cmd_receivepack)
{
	ssh_exec_subtransport *t = (ssh_exec_subtransport *)subtransport;

	git3__free(t->cmd_uploadpack);
	git3__free(t->cmd_receivepack);

	t->cmd_uploadpack = git3__strdup(cmd_uploadpack);
	GIT3_ERROR_CHECK_ALLOC(t->cmd_uploadpack);

	t->cmd_receivepack = git3__strdup(cmd_receivepack);
	GIT3_ERROR_CHECK_ALLOC(t->cmd_receivepack);

	return 0;
}

#endif
