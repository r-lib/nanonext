# minitest - a minimal testing framework v0.0.5 --------------------------------
test_library <- function(package) library(package = package, character.only = TRUE)
test_true <- function(x) invisible(isTRUE(x) || {print(x); stop("the above was returned instead of TRUE")})
test_false <- function(x) invisible(isFALSE(x) || {print(x); stop("the above was returned instead of FALSE")})
test_null <- function(x) invisible(is.null(x) || {print(x); stop("the above was returned instead of NULL")})
test_notnull <- function(x) invisible(!is.null(x) || stop("returns NULL when expected to be not NULL"))
test_zero <- function(x) invisible(x == 0L || {print(x); stop("the above was returned instead of 0L")})
test_type <- function(type, x) invisible(typeof(x) == type || {stop("object of type '", typeof(x), "' was returned instead of '", type, "'")})
test_class <- function(class, x) invisible(inherits(x, class) || {stop("object of class '", paste(class(x), collapse = ", "), "' was returned instead of '", class, "'")})
test_equal <- function(a, b) invisible(a == b || {print(a); print(b); stop("the above expressions were not equal")})
test_identical <- function(a, b) invisible(identical(a, b) || {print(a); print(b); stop("the above expressions were not identical")})
test_print <- function(x) invisible(is.character(capture.output(print(x))) || stop("print output of expression cannot be captured as a character value"))
test_error <- function(x, containing = "") invisible(inherits(x <- tryCatch(x, error = identity), "error") && grepl(containing, x[["message"]], fixed = TRUE) || stop("Expected error message containing: ", containing, "\nActual error message: ", x[["message"]]))
NOT_CRAN <- Sys.getenv("NOT_CRAN") == "true"
# ------------------------------------------------------------------------------

test_library("nanonext")
nng_version()

later <- requireNamespace("later", quietly = TRUE)
promises <- requireNamespace("promises", quietly = TRUE)

test_class("nanoObject", n <- nano("req", listen = "inproc://nanonext", autostart = FALSE))
test_class("nanoObject", n1 <- nano("rep", dial = "inproc://nanonext", autostart = FALSE))
test_true(is_nano(n))
test_class("nanoSocket", n$socket)
test_class("nano", n$socket)
n$newmethod <- "doesnotwork"
test_null(n$newmethod)
test_type("integer", attr(n$socket, "id"))
test_equal(n$socket$state, "opened")
test_equal(n$socket$protocol, "req")
test_equal(n$send("not ready", mode = "serial"), 8L)
test_equal(n$recv(), 11L)
test_class("nano", n$opt("recv-size-max", 8192))
test_equal(n$opt("recv-size-max"), 8192L)
test_class("nano", n$opt("recv-buffer", 8L))
test_class("nano", n$opt("req:resend-time", 0L))
test_class("nano", n$opt("socket-name", "nano"))
test_equal(n$opt("socket-name"), "nano")
test_error(n$opt("socket-name", NULL), "argument")
test_print(n$listener[[1]])
test_class("nanoListener", n$listener[[1]])
test_equal(n$listener[[1]]$url, "inproc://nanonext")
test_equal(n$listener[[1]]$state, "not started")
test_class("nano", n$listener_opt("recv-size-max", 1024)[[1L]])
test_equal(n$listener_opt("recv-size-max")[[1L]], 1024L)
test_error(n$listener_opt("false", 100), "supported")
test_error(n$listener_opt("false"), "supported")
test_error(n$listener_opt("false", "false"), "supported")
test_error(n$listener_opt("false", NULL), "supported")
test_error(n$listener_opt("false", TRUE), "supported")
test_error(n$listener_opt("false", list()), "type")
test_zero(n$listener_start())
test_equal(n$listener[[1]]$state, "started")
test_print(n1$dialer[[1]])
test_class("nanoDialer", n1$dialer[[1]])
test_equal(n1$dialer[[1]]$url, "inproc://nanonext")
test_equal(n1$dialer[[1]]$state, "not started")
test_class("nano", n1$dialer_opt("reconnect-time-min", 1000)[[1L]])
test_equal(n1$dialer_opt("reconnect-time-min")[[1L]], 1000L)
test_class("nano", n1$dialer_opt("recv-size-max", 8192)[[1L]])
test_equal(n1$dialer_opt("recv-size-max")[[1L]], 8192L)
test_error(n1$dialer_opt("false", 100), "supported")
test_error(n1$dialer_opt("false"), "supported")
test_error(n1$dialer_opt("false", "false"), "supported")
test_error(n1$dialer_opt("false", NULL), "supported")
test_error(n1$dialer_opt("false", TRUE), "supported")
test_error(n1$dialer_opt("false", list()), "type")
test_zero(n1$dialer_start())
test_equal(n1$dialer[[1]]$state, "started")

test_error(n$send(list(), mode = "raw"), "atomic vector type")
test_error(n$recv(mode = "none"), "mode")
test_error(n$recv(mode = "int"), "mode")
test_error(n$recv(mode = "logica"), "mode")
test_error(n$recv(mode = "charact"), "mode")
test_error(n$recv(mode = "positrons"), "mode")
test_true(is_aio(raio <- recv_aio(n$socket, timeout = 1L, cv = substitute())))
test_print(raio)
test_class("errorValue", call_aio(raio)$data)
test_class("errorValue", raio$data)
test_zero(pipe_id(raio))
r <- n$send(data.frame(), block = FALSE)
if (r == 8L) r <- n$send(data.frame(), block = 500L)
test_zero(r)
r <- n1$recv(block = FALSE)
if (is_error_value(r)) r <- n1$recv(block = 500)
test_class("data.frame", r)
test_zero(n1$send(c("test", "", "spec"), mode = "raw", block = 500))
test_identical(n$recv("character", block = 500), c("test", "", "spec"))
test_zero(n$send(1:5, mode = "raw"))
test_equal(length(n1$recv("integer", block = 500)), 5L)
test_true(is_aio(saio <- n1$send_aio(paste(replicate(5, random(1e3L)), collapse = ""), mode = 1L, timeout = 900)))
test_print(saio)
if (later) test_null(.keep(saio, new.env()))
test_class("sendAio", call_aio(saio))
test_zero(saio$result)
test_error(n$send("wrong mode", mode = "none"), "mode")
test_error(n$send("wrong mode", mode = "ser"), "mode")
test_error(n$send("wrong mode", mode = "rawial"), "mode")
test_class("recvAio", raio <- n$recv_aio(timeout = 500))
test_print(raio)
test_equal(nchar(call_aio(raio)[["value"]]), 10000L)
test_type("integer", pipe_id(raio))
raio$newfield <- "doesnotwork"
test_null(raio$newfield)
test_class("sendAio", saio <- n$send_aio(c(1.1, 2.2), mode = "raw", timeout = 500))
saio$newfield <- "doesnotwork"
test_null(saio$newfield)
test_type("logical", unresolved(saio))
test_type("logical", .unresolved(saio))
test_class("recvAio", msg <- n1$recv_aio(mode = "numeric", timeout = 500))
test_identical(call_aio(msg), msg)
test_class("recvAio", msg <- n1$recv_aio(mode = "complex", timeout = 500))
test_null(stop_aio(msg))
test_null(stop_aio(n))
test_false(stop_request(n))
test_identical(call_aio(msg), msg)
test_class("errorValue", msg$data)
test_identical(call_aio(n), n)
test_class("sendAio", sraio <- n$send_aio(as.raw(0L), mode = "raw", timeout = 500))
test_class("recvAio", rraio <- n1$recv_aio(mode = 1L, timeout = 500))
test_true(is_nul_byte(suppressWarnings(call_aio_(rraio)$data)))
test_class("sendAio", sraio <- n$send_aio(as.raw(1L), mode = 2L, timeout = 500))
test_class("recvAio", rraio <- n1$recv_aio(mode = "raw", timeout = 500))
test_type("raw", call_aio(rraio)$data)
test_class("sendAio", sraio <- n$send_aio(c(1+2i, 4+3i), mode = "raw", timeout = 500))
test_class("recvAio", rraio <- n1$recv_aio(mode = "complex", timeout = 500))
test_type("complex", call_aio(rraio)$data)
test_class("sendAio", sraio <- n$send_aio(5, mode = "raw", timeout = 500))
test_class("recvAio", rraio <- n1$recv_aio(mode = "double", timeout = 500))
test_type("double", call_aio(rraio)$data)
test_class("sendAio", sraio <- n$send_aio(c(1, 2), mode = "raw", timeout = 500))
test_class("recvAio", rraio <- n1$recv_aio(mode = "numeric", timeout = 500))
test_true(is.numeric(call_aio(rraio)$data))
test_class("sendAio", sraio <- n$send_aio(c(1L, 2L, 3L), mode = "raw", timeout = 500))
test_class("recvAio", rraio <- n1$recv_aio(mode = "integer", timeout = 500))
test_type("integer", call_aio(rraio)$data)
test_class("sendAio", sraio <- n$send_aio(as.raw(0L), mode = "raw", timeout = 500))
test_class("recvAio", rraio <- n1$recv_aio(mode = "double", timeout = 500))
test_type("raw", suppressWarnings(call_aio(rraio)$data))
test_class("sendAio", sraio <- n$send_aio(as.raw(0L), mode = "raw", timeout = 500))
test_class("recvAio", rraio <- n1$recv_aio(mode = "integer", timeout = 500))
test_type("raw", suppressWarnings(call_aio(rraio)$data))
test_class("sendAio", sraio <- n$send_aio(as.raw(0L), mode = "raw", timeout = 500))
test_class("recvAio", rraio <- n1$recv_aio(mode = "logical", timeout = 500))
test_type("raw", suppressWarnings(collect_aio(rraio)))
test_class("sendAio", sraio <- n$send_aio(as.raw(0L), mode = "raw", timeout = 500))
test_class("recvAio", rraio <- n1$recv_aio(mode = "numeric", timeout = 500))
test_type("raw", suppressWarnings(rraio[]))
test_class("sendAio", sraio <- n$send_aio(as.raw(0L), mode = "raw", timeout = 500))
test_class("recvAio", rraio <- n1$recv_aio(mode = "complex", timeout = 500))
test_type("raw", suppressWarnings(collect_aio_(rraio)))
rcv <- cv()
test_equal(race_aio(list(rraio), rcv), 1L)
test_equal(race_aio(list(sraio, rraio), rcv), 1L)
test_equal(race_aio(list(rraio), NULL), 1L)
test_equal(race_aio(list(rraio), "invalid"), 1L)
rtest <- recv_aio(n1$socket, timeout = 100, cv = rcv)
test_equal(race_aio(list(rtest), rcv), 1L)
test_error(opt(rraio[["aio"]], "false") <- 0L, "valid")
test_error(subscribe(rraio[["aio"]], "false"), "valid")
test_error(opt(rraio[["aio"]], "false"), "valid")
test_error(stat(rraio[["aio"]], "pipes"), "valid")

test_zero(n$dial(url = "inproc://two", autostart = FALSE))
test_zero(n$dialer_start())
test_class("nanoDialer", n$dialer[[1L]])
test_type("double", stat(n$dialer[[1L]], "id"))
test_zero(n$listen(url = "inproc://three", autostart = FALSE))
test_zero(n$listener_start())
test_class("nanoListener", n$listener[[2L]])
test_type("double", stat(n$listener[[2L]], "id"))
test_zero(n$dial(url = "inproc://four"))
test_zero(close(n$listener[[1]]))
test_equal(suppressWarnings(start(n$listener[[1]])), 12L)
test_equal(suppressWarnings(close(n$listener[[1]])), 12L)
test_zero(close(n1$dialer[[1]]))
test_equal(suppressWarnings(start(n1$dialer[[1]])), 12L)
test_equal(suppressWarnings(close(n1$dialer[[1]])), 12L)
test_zero(reap(n$listener[[2]]))
test_zero(reap(n$dialer[[2]]))
test_zero(n$close())
test_zero(n1$close())
test_equal(suppressWarnings(n1$close()), 7L)
test_equal(n$socket[["state"]], "closed")
test_equal(n1$socket[state], "closed")

test_class("conditionVariable", cv <- cv())
test_print(cv)
test_false(until(cv, 10L))
test_false(until(cv, 10))
test_false(until_(cv, 10L))
test_false(until_(cv, 10))
test_false(until_(cv, "test"))
test_zero(cv_reset(cv))
test_zero(cv_value(cv))

test_class("nanoObject", req <- nano("req", listen = "inproc://testing"))
test_class("nanoSocket", rep <- socket("rep", dial = "inproc://testing", listen = "inproc://testing2"))
test_print(rep)
test_equal(stat(rep, "dialers"), 1)
test_equal(stat(rep, "protocol"), "rep")
test_null(stat(rep, "nonexistentstat"))
test_class("nano", req$opt("req:resend-time", 1000))
test_equal(req$opt("req:resend-time"), 1000L)
test_error(req$opt("none"), "supported")
test_type("externalptr", req$context_open())
test_class("nanoContext", req$context)
test_class("nano", req$context)
test_type("integer", req$context$id)
test_equal(req$context$state, "opened")
test_equal(req$context$protocol, "req")
test_class("nano", req$opt("send-timeout", 1000))
test_equal(req$opt("send-timeout"), 1000L)
test_error(req$opt("false", 100), "supported")
test_error(req$opt("false"), "supported")
test_error(req$opt("false", "false"), "supported")
test_error(req$opt("false", NULL), "supported")
test_error(req$opt("false", TRUE), "supported")
test_error(req$opt("false", list()), "type")

test_class("nanoContext", ctx <- context(rep))
test_print(ctx)
test_true(.mark())
test_class("sendAio", csaio <- req$send_aio(data.frame(), mode = 1L, timeout = 500))
test_zero(call_aio_(csaio)$result)
test_class("recvAio", craio <- recv_aio(ctx, mode = 8L, timeout = 500))
test_type("raw", res <- collect_aio(craio))
test_true(.read_marker(res))
test_false(.read_marker("not"))
test_equal(.read_header("not"), 0L)
test_type("list", unserialize(res[9:length(res)]))
test_false(.mark(FALSE))
test_zero(req$send("context test", mode ="raw", block = 500))
test_equal(recv(ctx, mode = "string", block = 500), "context test")
test_type("integer", req$send(data.frame(), mode = "serial", block = 500))
test_class("recvAio", msg <- recv_aio(ctx, mode = "serial", timeout = 500))
test_type("logical", .unresolved(msg))
test_type("logical", unresolved(msg))
test_class("data.frame", call_aio(msg)$data)
test_false(unresolved(msg))
test_zero(req$send(c(TRUE, FALSE, TRUE), mode = 2L, block = 500))
test_class("recvAio", msg <- recv_aio(ctx, mode = 6L, timeout = 500))
test_type("logical", msg[])
test_identical(collect_aio(msg), collect_aio_(msg))
test_class("sendAio", err <- send_aio(ctx, msg[["data"]], mode = "serial"))
test_null(stop_aio(err))
test_class("sendAio", err <- send_aio(ctx, "test"))
test_class("errorValue", call_aio(err)$result)
test_class("errorValue", call_aio(list(err))[[1L]][["result"]])
test_class("errorValue", call_aio_(err)$result)
test_class("errorValue", call_aio_(list(item = err))[["item"]][["result"]])
test_class("errorValue", collect_aio(err))
test_class("errorValue", collect_aio(list(item = err))[["item"]])
test_class("errorValue", collect_aio_(list(err))[[1L]])
test_zero(req$send(serialize(NULL, NULL, ascii = TRUE), mode = 2L, block = 500))
test_null(call_aio(recv_aio(ctx, mode = 1L, timeout = 500))[["value"]])
test_class("sendAio", saio <- send_aio(ctx, as.raw(1L), mode = 2L, timeout = 500))
test_identical(req$recv(mode = 8L, block = 500), as.raw(1L))
test_class("recvAio", rek <- request(req$context, c(1+3i, 4+2i), send_mode = 2L, recv_mode = "complex", timeout = 500))
test_zero(reply(ctx, execute = identity, recv_mode = 3L, send_mode = "raw", timeout = 500))
test_type("complex", call_aio(rek)[["data"]])
test_class("recvAio", rek <- request(req$context, c(1+3i, 4+2i), send_mode = "serial", recv_mode = "serial", timeout = 500))
test_zero(reply(ctx, execute = identity, recv_mode = 1L, send_mode = 1L, timeout = 500))
test_type("complex", call_aio(rek)[["data"]])
test_type("integer", rek[["aio"]])

test_type("list", cfg <- serial_config(class = c("invalid", "custom"), sfunc = list(identity, function(x) raw(1L)), ufunc = list(identity, as.integer)))
opt(req$socket, "serial") <- cfg
opt(rep, "serial") <- cfg
custom <- list(`class<-`(new.env(), "custom"), new.env())
test_zero(send(req$socket, custom, mode = "serial", block = 500))
test_type("integer", recv(rep, block = 500)[[1L]])
custom <- list(`class<-`(new.env(), "unused"), new.env())
test_zero(send(req$socket, custom, mode = "serial", block = 500))
test_type("list", recv(rep, block = 500))
cfg <- serial_config("custom", function(x) as.raw(length(x)), function(x) lapply(seq_len(as.integer(x)), new.env))
test_type("list", cfg)
opt(req$socket, "serial") <- cfg
opt(rep, "serial") <- cfg
test_zero(send(rep, custom, block = 500))
test_type("list", recv(req$socket, mode = 1L, block = 500))
cfg <- serial_config(c("error_env", "string_class"), list(function(x) stop("serialization failue"), function(x) "serialized string"), list(function(x) stop(), function(x) stop()))
opt(req$socket, "serial") <- cfg
test_error(send(req$socket, `class<-`(new.env(), "error_env"), block = 500), "serialization failue")
test_error(send(req$socket, `class<-`(new.env(), "string_class"), block = 500), "string_class")
opt(req$socket, "serial") <- cfg
opt(req$socket, "serial") <- list()
opt(rep, "serial") <- list()
test_error(serial_config(1L, identity, identity), "must be a character vector")
test_error(serial_config(c("custom", "custom2"), list(identity), list(identity)), "must all be the same length")
test_error(serial_config("custom", "func1", "func2"), "must be a function or list of functions")
test_error(serial_config("custom", identity, "func2"), "must be a function or list of functions")
test_error(opt(rep, "wrong") <- cfg, "not supported")
test_error(opt(rep, "serial") <- pairlist(a = 1L), "not supported")

test_class("recvAio", cs <- request(req$context, "test", send_mode = "serial", cv = cv, timeout = 500, id = TRUE))
test_notnull(cs$data)
test_type("externalptr", ctxn <- .context(rep))
test_class("recvAio", cr <- recv_aio(ctxn, mode = 8L, cv = cv, timeout = 500))
test_equal(.read_header(call_aio(cr)$data), 1L)
test_type("integer", cr$aio)
test_type("integer", send(ctxn, TRUE, mode = 0L, block = FALSE))
test_type("externalptr", ctxn <- .context(rep))
test_class("recvAio", cs <- request(.context(req$socket), data = TRUE, cv = NA, id = TRUE))
test_notnull(cs$data)
test_true(recv(ctxn, block = 500))
test_zero(send(ctxn, TRUE, mode = 1L, block = 500))
test_class("recvAio", cs <- request(.context(req$socket), data = TRUE, timeout = 5, id = TRUE))
test_false(stop_request(cs))
test_zero(reap(ctxn))
test_equal(reap(ctxn), 7L)
test_zero(pipe_notify(rep, cv, add = TRUE, flag = TRUE))
test_zero(pipe_notify(rep, cv, remove = TRUE, flag = tools::SIGCONT))
test_zero(pipe_notify(req$socket, cv = cv, add = TRUE))
test_error(request(err, "test", cv = cv), "valid")
test_error(recv_aio(err, cv = cv, timeout = 500))
test_error(wait(err), "valid")
test_error(wait_(err), "valid")
test_error(until(err, 10), "valid")
test_error(until_(err, 10), "valid")
test_error(cv_value(err), "valid")
test_error(cv_reset(err), "valid")
test_error(cv_signal(err), "valid")
test_error(pipe_notify(err, cv), "valid Socket")
test_error(pipe_notify(rep, err), "valid Condition Variable")
test_zero(req$context_close())
test_null(req$context_close)
test_zero(req$close())
test_null(req$context)
rep$dialer <- NULL
test_type("externalptr", rep$dialer[[1L]])
test_zero(close(ctx))
test_equal(suppressWarnings(close(ctx)), 7L)
test_zero(close(rep))

test_class("nanoObject", pub <- nano("pub", listen = "inproc://ps"))
test_class("nanoObject", sub <- nano("sub", dial = "inproc://ps", autostart = NA))
test_zero(cv_reset(cv))
test_zero(pipe_notify(pub$socket, cv, add = TRUE, remove = TRUE))
test_class("nano", sub$opt(name = "sub:prefnew", value = FALSE))
test_false(sub$opt(name = "sub:prefnew"))
test_error(sub$opt(name = "false", value = 100), "supported")
test_error(sub$opt(name = "false"), "supported")
test_error(sub$opt(name = "false", value = list()), "type")
test_class("nano", sub$subscribe("test"))
test_class("nano", subscribe(sub$socket, NULL))
test_class("nano", sub$unsubscribe("test"))
test_type("externalptr", sub$context_open())
test_class("nanoContext", sub$context)
test_class("nano", sub$subscribe(12))
test_class("nano", sub$unsubscribe(12))
test_class("nano", sub$subscribe(NULL))
test_zero(sub$context_close())
test_null(sub$context)
test_zero(sub$close())
test_zero(pub$close())
test_true(wait(cv))
test_type("externalptr", cv2 <- cv())
test_type("externalptr", cv3 <- cv())
test_type("externalptr", cv %~>% cv2 %~>% cv3)
test_zero(cv_signal(cv))
test_equal(cv_value(cv), 1L)
test_true(wait_(cv3))
test_type("externalptr", cv %~>% cv3)
test_error("a" %~>% cv3, "valid Condition Variable")
test_error(cv3 %~>% "a", "valid Condition Variable")

test_class("nanoObject", surv <- nano(protocol = "surveyor", listen = "inproc://sock1", dial = "inproc://sock2"))
test_print(surv)
test_class("nanoObject", resp <- nano(protocol = "respondent", listen = "inproc://sock2", dial = "inproc://sock1"))
test_zero(pipe_notify(surv$socket, cv, add = TRUE, remove = TRUE, flag = TRUE))
surv$dialer <- NULL
test_type("externalptr", surv$dialer[[1L]])
test_type("externalptr", surv$listener[[1L]])
test_class("nano", surv$survey_time(50))
test_zero(surv$send("survey", block = 500))
test_class("errorValue", surv$recv(block = 200))
test_type("externalptr", surv$context_open())
test_type("externalptr", resp$context_open())
test_class("nano", surv$survey_time(value = 2000))
test_zero(surv$context_close())
test_zero(resp$context_close())
test_zero(surv$close())
test_zero(resp$close())
test_false(wait(cv))
test_class("errorValue", resp$recv())

test_class("nanoObject", poly <- nano(protocol = "poly", listen = "inproc://polytest"))
test_equal(formals(poly$send)$pipe, 0L)
test_equal(formals(poly$send_aio)$pipe, 0L)
test_zero(poly$close())

test_zero(cv_reset(cv))
test_class("nanoSocket", poly <- socket(protocol = "poly"))
test_class("nanoSocket", poly1 <- socket(protocol = "poly"))
test_class("nanoSocket", poly2 <- socket(protocol = "poly"))
test_class("nanoMonitor", m <- monitor(poly, cv))
test_print(m)
test_zero(listen(poly))
test_null(read_monitor(m))
test_class("sendAio", send_aio(poly, "one", timeout = 50))
invisible(gc())
test_null(msleep(55))
test_zero(dial(poly1))
test_zero(dial(poly2))
test_true(wait(cv))
test_true(wait(cv))
test_equal(length(pipes <- read_monitor(m)), 2L)
test_zero(send_aio(poly, "one", timeout = 500, pipe = pipes[1L])[])
test_zero(send(poly, "two", block = 500, pipe = pipes[2L]))
test_type("integer", send(poly, "two", block = FALSE, pipe = pipes[2L]))
test_type("character", recv(poly1, block = 500))
test_type("character", recv(poly2, block = 500))
test_zero(reap(poly2))
test_zero(reap(poly1))
test_true(wait(cv))
test_type("integer", read_monitor(m))
test_error(read_monitor(poly), "valid Monitor")
test_error(monitor("socket", "cv"), "valid Socket")
test_error(monitor(poly, "cv"), "valid Condition Variable")
test_zero(reap(poly))

test_class("nanoSocket", bus <- socket(protocol = "bus"))
test_class("nanoSocket", push <- socket(protocol = "push"))
test_class("nanoSocket", pull <- socket(protocol = "pull"))
test_class("nanoSocket", pair <- socket(protocol = "pair"))
test_class("nano", bus)
test_equal(suppressWarnings(listen(bus, url = "test", fail = "warn")), 3L)
test_error(listen(bus, url = "test", fail = "error"), "argument")
test_equal(listen(bus, url = "test", fail = "none"), 3L)
test_equal(suppressWarnings(dial(bus, url = "test", fail = 1L)), 3L)
test_error(dial(bus, url = "test", fail = 2L), "argument")
test_equal(dial(bus, url = "test", fail = 3L), 3L)
test_error(listen(bus, url = "tls+tcp://localhost/:0", tls = "wrong"), "valid TLS")
test_error(dial(bus, url = "tls+tcp://localhost/:0", tls = "wrong"), "valid TLS")
test_zero(close(bus))
test_equal(suppressWarnings(close(bus)), 7L)
test_zero(close(push))
test_zero(close(pull))
test_zero(reap(pair))

test_error(socket(protocol = "newprotocol"), "protocol")
test_error(socket(dial = "test"), "argument")
test_error(socket(listen = "test"), "argument")

test_type("list", ncurl("http://www.cam.ac.uk/"))
test_type("list", res <- ncurl("http://www.cam.ac.uk/", follow = FALSE, response = TRUE))
if (res$status == 301L) test_true(length(res$headers) > 1L)
test_type("list", ncurl("http://www.cam.ac.uk/", follow = TRUE))
test_type("list", ncurl("https://postman-echo.com/post", convert = FALSE, method = "POST", headers = c(`Content-Type` = "application/octet-stream"), data = as.raw(1L), response = c("Date", "Server"), timeout = 3000))
test_class("errorValue", ncurl("http")$data)
test_class("recvAio", haio <- ncurl_aio("http://www.cam.ac.uk/", timeout = 3000L))
test_true(is_aio(haio))
test_type("integer", call_aio(haio)$status)
test_class("ncurlAio", haio <- ncurl_aio("https://www.cam.ac.uk/", convert = FALSE, response = "server", timeout = 3000L))
test_notnull(haio$status)
if (call_aio(haio)$status == 200L) test_notnull(haio$headers)
test_class("ncurlAio", put1 <- ncurl_aio("https://postman-echo.com/put", method = "PUT", headers = c(`Content-Type` = "text/plain", Authorization = "Bearer token"), data = "test", response = TRUE, timeout = 3000L))
test_print(put1)
test_type("integer", call_aio_(put1)$status)
if (put1$status == 200L) test_notnull(put1$headers)
if (put1$status == 200L) test_notnull(put1$data)
test_null(stop_aio(put1))
test_false(stop_request(put1))
test_class("ncurlAio", haio <- ncurl_aio("https://i.i"))
test_class("errorValue", call_aio(haio)$data)
test_print(haio$data)
test_class("ncurlAio", ncaio <- ncurl_aio("https://nanonext.r-lib.org/reference/figures/logo.png"))
if (suppressWarnings(call_aio(ncaio)$status == 200L)) test_type("raw", ncaio$data)
test_class("errorValue", ncurl_aio("http")$data)
sess <- ncurl_session("https://postman-echo.com/post", method = "POST", headers = c(`Content-Type` = "text/plain"), data = "test", response = c("date", "Server"), timeout = 3000L)
test_true(is_ncurl_session(sess) || is_error_value(sess))
if (is_ncurl_session(sess)) test_equal(length(transact(sess)), 3L)
if (is_ncurl_session(sess)) test_zero(close(sess))
if (is_ncurl_session(sess)) test_equal(suppressWarnings(close(sess)), 7L)
sess <- ncurl_session("https://postman-echo.com/post", convert = FALSE, method = "POST", headers = c(`Content-Type` = "text/plain"), timeout = 3000)
test_true(is_ncurl_session(sess) || is_error_value(sess))
if (is_ncurl_session(sess)) test_equal(length(transact(sess)), 3L)
if (is_ncurl_session(sess)) test_zero(close(sess))
if (is_ncurl_session(sess)) test_equal(transact(sess)$data, 7L)
sess_all <- ncurl_session("https://postman-echo.com/get", response = TRUE, timeout = 3000L)
test_true(is_ncurl_session(sess_all) || is_error_value(sess_all))
if (is_ncurl_session(sess_all)) {
  trans_all <- transact(sess_all)
  test_true(length(trans_all$headers) > 0L)
  test_zero(close(sess_all))
}
test_class("errorValue", suppressWarnings(ncurl_session("https://i")))
test_error(ncurl_aio("https://", tls = "wrong"), "valid TLS")
test_error(ncurl("https://www.cam.ac.uk/", tls = "wrong"), "valid TLS")
test_type("externalptr", etls <- tls_config())
test_error(stream(dial = "wss://127.0.0.1:5555", textframes = TRUE, tls = etls))
test_error(stream(dial = "wss://127.0.0.1:5555"))
test_error(stream(dial = "errorValue3"), "argument")
test_error(stream(dial = "inproc://notsup"), "Not supported")
test_error(stream(dial = "wss://127.0.0.1:5555", tls = "wrong"), "valid TLS")
test_error(stream(listen = "errorValue3"), "argument")
test_error(stream(listen = "inproc://notsup"), "Not supported")
test_error(stream(listen = "errorValue3", tls = "wrong"), "valid TLS")
test_error(stream(), "specify a URL")

test_type("character", ver <- nng_version())
test_equal(length(ver), 2L)
test_equal(nng_error(5L), "5 | Timed out")
test_equal(nng_error(8), "8 | Try again")
test_true(is_nul_byte(as.raw(0L)))
test_false(is_nul_byte(NULL))
test_false(is_error_value(1L))
test_error(messenger("invalidURL"), "argument")
test_type("raw", md5 <- nanonext:::md5_object("secret base"))
test_equal(length(md5), 32L)
test_type("double", mclock())
test_null(msleep(1L))
test_null(msleep(1))
test_null(msleep("a"))
test_null(msleep(-1L))
test_type("character", urlp <- parse_url("://"))
test_equal(length(urlp), 7L)
test_true(all(nzchar(parse_url("wss://use:r@[::1]/path?q=1#name"))))
test_type("character", random())
test_equal(nchar(random(1)), 2L)
test_equal(nchar(random(1024)), 2048L)
test_equal(length(random(4L, convert = FALSE)), 4L)
test_error(random(1025), "between 1 and 1024")
test_error(random(0), "between 1 and 1024")
test_error(random(-1), "between 1 and 1024")
test_error(random("test"), "integer")
test_error(parse_url("tcp:/"), "argument")
test_equal(parse_url("://missing/scheme")["scheme"], "")
test_equal(parse_url("tcp://")["port"], "")
for (i in c(100:103, 200:208, 226, 300:308, 400:426, 428:431, 451, 500:511, 600))
  test_type("character", status_code(i))

s <- tryCatch(stream(dial = "wss://echo.websocket.org/", textframes = TRUE), error = function(e) NULL)
if (is_nano(s)) test_notnull(recv(s, block = 500L))
if (is_nano(s)) test_type("character", opt(s, "ws:response-headers"))
if (is_nano(s)) test_error(opt(s, "ws:request-headers") <- "test\n", 24)
if (is_nano(s)) test_type("integer", send(s, c("message1", "test"), block = 500L))
if (is_nano(s)) test_notnull(recv(s, block = FALSE))
if (is_nano(s)) test_type("integer", send(s, "message2", block = FALSE))
if (is_nano(s)) test_notnull(suppressWarnings(recv(s, mode = 9L, block = 100)))
if (is_nano(s)) test_type("integer", send(s, 2L, block = 500))
if (is_nano(s)) test_class("recvAio", sr <- recv_aio(s, mode = "integer", timeout = 500L, n = 8192L))
if (is_nano(s)) test_notnull(suppressWarnings(call_aio(sr)[["data"]]))
if (is_nano(s)) test_null(stop_aio(sr))
if (is_nano(s)) test_class("sendAio", ss <- send_aio(s, "async", timeout = 500L))
if (is_nano(s)) test_type("integer", ss[])
if (is_nano(s)) test_null(stop_aio(ss))
if (is_nano(s)) test_type("integer", send(s, 12.56, mode = "raw", block = 500L))
if (is_nano(s)) test_class("recvAio", sr <- recv_aio(s, mode = "double", timeout = 500L, cv = cv))
if (is_nano(s)) test_notnull(suppressWarnings(call_aio_(sr)[["data"]]))
if (is_nano(s)) test_true(cv_value(cv) > 0L)
if (is_nano(s)) test_type("character", opt(s, "ws:request-headers"))
if (is_nano(s)) test_notnull(opt(s, "tcp-nodelay") <- FALSE)
if (is_nano(s)) test_error(opt(s, "none"), "supported")
if (is_nano(s)) test_error(`opt<-`(s, "none", list()), "supported")
if (is_nano(s)) test_print(s)
if (is_nano(s)) test_type("integer", close(s))

test_equal(nanonext:::.DollarNames.ncurlAio(NULL, "sta"), "status")
test_equal(nanonext:::.DollarNames.recvAio(NULL, "dat"), "data")
test_equal(nanonext:::.DollarNames.sendAio(NULL, "r"), "result")
test_zero(length(nanonext:::.DollarNames.nano(NULL)))

fakesock <- `class<-`(new.env(), "nanoSocket")
test_error(dial(fakesock), "valid Socket")
test_error(dial(fakesock, autostart = FALSE), "valid Socket")
test_error(listen(fakesock), "valid Socket")
test_error(listen(fakesock, autostart = FALSE), "valid Socket")
test_error(context(fakesock), "valid Socket")
test_error(.context(fakesock), "valid Socket")
test_error(stat(fakesock, "pipes"), "valid Socket")
test_error(close(fakesock), "valid Socket")
test_false(.unresolved(fakesock))
fakectx <- `class<-`("test", "nanoContext")
test_false(unresolved(fakectx))
test_false(.unresolved(fakectx))
test_error(request(fakectx, data = "test"), "valid Context")
test_error(subscribe(fakectx, NULL), "valid")
test_error(close(fakectx), "valid Context")
test_equal(reap(fakectx), 3L)
fakestream <- `class<-`("test", "nanoStream")
test_print(fakestream)
fakesession <- `class<-`("test", "ncurlSession")
test_print(fakesession)
test_error(transact(fakesession), "valid")
test_error(close(fakesession), "valid")
test_error(send(fakestream, "test"), "valid")
test_error(send_aio(fakestream, "test"), "valid")
test_error(recv(fakestream), "valid")
test_error(recv_aio(fakestream), "valid")
test_error(opt(fakestream, name = "test") <- "test", "valid")
test_error(opt(fakestream, name = "test"), "valid")
test_equal(close(fakestream), 7L)
fakedial <- `class<-`("test", "nanoDialer")
test_error(start(fakedial), "valid Dialer")
test_error(close(fakedial), "valid Dialer")
fakelist <- `class<-`("test", "nanoListener")
test_error(start(fakelist), "valid Listener")
test_error(close(fakelist), "valid Listener")
unres <- `class<-`(NA, "unresolvedValue")
test_false(unresolved(unres))
test_print(unres)
test_type("logical", unres <- unresolved(list("a", "b")))
test_equal(length(unres), 1L)
test_type("integer", unres <- .unresolved(list("a", "b")))
test_equal(length(unres), 1L)
test_zero(race_aio(list(), cv()))
test_zero(race_aio("not a list", cv()))
test_zero(race_aio(list("a", "b"), cv()))
test_identical(call_aio("a"), "a")
test_identical(call_aio_("a"), "a")
test_error(collect_aio_("a"), "object is not an Aio or list of Aios")
test_error(collect_aio_(list("a")), "object is not an Aio or list of Aios")
test_error(collect_aio(list(fakesock)), "object is not an Aio or list of Aios")
test_null(stop_aio("a"))
test_false(stop_request("a"))
test_null(stop_aio(list("a")))
test_false(stop_request(list("a")))
test_null(.keep(NULL, new.env()))
test_null(.keep(new.env(), new.env()))

pem <- "-----BEGIN CERTIFICATE----- -----END CERTIFICATE-----"
test_tls <- function(pem) {
  file <- tempfile()
  on.exit(unlink(file))
  cat(pem, file = file)
  test_error(tls_config(client = file), "Cryptographic error")
  test_error(tls_config(server = file), "Cryptographic error")
}
test_true(test_tls(pem = pem))
test_error(tls_config(client = c(pem, pem)), "Cryptographic error")
test_error(tls_config(server = c(pem, pem)), "Cryptographic error")
test_type("list", cert <- write_cert(cn = "127.0.0.1"))
test_equal(length(cert), 2L)
test_type("character", cert[[1L]])
test_identical(names(cert), c("server", "client"))
test_type("externalptr", tls <- tls_config(client = cert$client))
test_class("tlsConfig", tls)
test_print(tls)
test_class("errorValue", ncurl("https://www.cam.ac.uk/", tls = tls)$status)
test_class("errorValue", call_aio(ncurl_aio("https://www.cam.ac.uk/", tls = tls))$data)
test_error(ncurl_session("https://www.cam.ac.uk/", tls = cert$client), "not a valid TLS")
sess <- ncurl_session("https://www.cam.ac.uk/", tls = tls)
test_true(is_ncurl_session(sess) || is_error_value(sess))
if (is_ncurl_session(sess)) test_class("errorValue", transact(sess)[["headers"]])
test_type("externalptr", s <- socket(listen = "tls+tcp://127.0.0.1:5556", tls = tls_config(server = cert$server)))
test_type("externalptr", s1 <- socket(dial = "tls+tcp://127.0.0.1:5556", tls = tls))
test_true(suppressWarnings(dial(s, url = "tls+tcp://.", tls = tls)) > 0)
test_true(suppressWarnings(listen(s, url = "tls+tcp://.", tls = tls)) > 0)
test_zero(close(s1))
test_zero(close(s))
if (promises) test_class("nano", s <- socket(listen = "inproc://nanonext"))
if (promises) test_class("nano", s1 <- socket(dial = "inproc://nanonext"))
if (promises) test_class("recvAio", r <- recv_aio(s, timeout = 500L))
if (promises) test_true(promises::is.promise(promises::then(r, identity, identity)))
if (promises) test_type("integer", send(s1, "promises test\n", block = 500L))
if (promises) test_class("recvAio", r2 <- recv_aio(s, timeout = 1L))
if (promises) test_true(promises::is.promising(call_aio(r2)))
if (promises) test_true(promises::is.promise(promises::then(r2, identity, identity)))
if (promises) test_true(promises::is.promising(call_aio(r)))
if (promises) test_type("integer", send(s1, "promises test2\n", block = 500L))
if (promises) test_true(promises::is.promise(promises::then(call_aio(recv_aio(s, timeout = 500L)), identity, identity)))
if (promises) test_true(is_aio(n <- ncurl_aio("https://www.cam.ac.uk/", timeout = 3000L)))
if (promises) test_true(promises::is.promise(promises::then(n, identity, identity)))
if (promises) test_true(promises::is.promising(call_aio(n)))
if (promises) test_true(promises::is.promise(promises::as.promise(call_aio(ncurl_aio("https://www.cam.ac.uk/", timeout = 3000L)))))
if (promises) { later::run_now(1L); later::run_now() }
if (promises) test_zero(close(s1))
if (promises) test_zero(close(s))
if (promises) { later::run_now(1L); later::run_now() }
test_type("character", ip_addr())
test_type("character", names(ip_addr()))
test_null(write_stdout(""))
test_false(identical(get0(".Random.seed"), {.advance(); .Random.seed}))
test_type("integer", .Call(nanonext:::rnng_traverse_precious))

test_error(.dispatcher("invalid", NULL, NULL, NULL, NULL, NULL, NULL), "valid Socket")
test_class("nanoSocket", dsock <- socket("rep"))
test_error(.dispatcher(dsock, "invalid", NULL, NULL, NULL, NULL, NULL), "valid Socket")
test_class("nanoSocket", dpsock <- socket("poly"))
test_error(.dispatcher(dsock, dpsock, "invalid", NULL, NULL, NULL, NULL), "valid Monitor")
test_zero(close(dpsock))
test_zero(close(dsock))

if (NOT_CRAN) {
  if (.Platform$OS.type == "windows") {
    url_rep <- sprintf("ipc://nanonext-rep-%d", Sys.getpid())
    url_poly <- sprintf("ipc://nanonext-poly-%d", Sys.getpid())
  } else {
    url_rep <- sprintf("ipc://%s", tempfile())
    url_poly <- sprintf("ipc://%s", tempfile())
  }
  dispatcher_code <- sprintf('
    library(nanonext)
    cv <- cv()
    rep_sock <- socket("rep", listen = "%s")
    poly_sock <- socket("poly", listen = "%s")
    mon <- monitor(poly_sock, cv)
    pipe_notify(rep_sock, cv, remove = TRUE, flag = tools::SIGTERM)
    .dispatcher(rep_sock, poly_sock, mon, raw(10), NULL, new.env(), function(e) NULL)
    close(poly_sock)
  ', url_rep, url_poly)
  script <- tempfile(fileext = ".R")
  writeLines(dispatcher_code, script)
  Rscript <- file.path(R.home("bin"), if (.Platform$OS.type == "windows") "Rscript.exe" else "Rscript")
  system2(Rscript, script, wait = FALSE, stdout = FALSE, stderr = FALSE)
  Sys.sleep(0.5)
  daemon <- socket("poly", dial = url_poly)
  Sys.sleep(0.3)
  init_data <- recv(daemon, mode = "raw", block = 2000)
  test_type("raw", init_data)
  client <- socket("req", dial = url_rep)
  Sys.sleep(0.1)
  send(client, raw(8), mode = "raw", block = 2000)
  status <- recv(client, mode = "integer", block = 2000)
  test_equal(length(status), 5L)
  test_true(status[1L] >= 1L)
  test_true(status[2L] >= 1L)
  cancel_msg <- raw(8)
  cancel_msg[5] <- as.raw(99L)
  send(client, cancel_msg, mode = "raw", block = 2000)
  cancel_result <- recv(client, mode = "integer", block = 2000)
  test_equal(cancel_result, 0L)
  task_exec <- raw(13)
  task_exec[1] <- as.raw(0x07)
  task_exec[5] <- as.raw(60L)
  send(client, task_exec, mode = "raw", block = 2000)
  task_exec_recv <- recv(daemon, mode = "raw", block = 2000)
  test_type("raw", task_exec_recv)
  cancel_exec <- raw(8)
  cancel_exec[5] <- as.raw(60L)
  send(client, cancel_exec, mode = "raw", block = 2000)
  cancel_exec_res <- recv(client, mode = "integer", block = 2000)
  test_equal(cancel_exec_res, 1L)
  cancel_sig <- recv(daemon, mode = "raw", block = 2000)
  test_equal(length(cancel_sig), 0L)
  send(daemon, raw(13), mode = "raw", block = 2000)
  recv(client, mode = "raw", block = 2000)
  task_busy <- raw(13)
  task_busy[1] <- as.raw(0x07)
  task_busy[5] <- as.raw(70L)
  send(client, task_busy, mode = "raw", block = 2000)
  task_queued <- raw(13)
  task_queued[1] <- as.raw(0x07)
  task_queued[5] <- as.raw(71L)
  send(client, task_queued, mode = "raw", block = 2000)
  cancel_inq <- raw(8)
  cancel_inq[5] <- as.raw(71L)
  send(client, cancel_inq, mode = "raw", block = 2000)
  cancel_inq_res <- recv(client, mode = "integer", block = 2000)
  test_equal(cancel_inq_res, 1L)
  recv(daemon, mode = "raw", block = 2000)
  send(daemon, raw(13), mode = "raw", block = 2000)
  recv(client, mode = "raw", block = 2000)
  task_q1 <- raw(13)
  task_q1[1] <- as.raw(0x07)
  task_q1[5] <- as.raw(72L)
  send(client, task_q1, mode = "raw", block = 2000)
  task_q2 <- raw(13)
  task_q2[1] <- as.raw(0x07)
  task_q2[5] <- as.raw(73L)
  send(client, task_q2, mode = "raw", block = 2000)
  recv(daemon, mode = "raw", block = 2000)
  send(daemon, raw(13), mode = "raw", block = 2000)
  recv(client, mode = "raw", block = 2000)
  q2_recv <- recv(daemon, mode = "raw", block = 2000)
  test_type("raw", q2_recv)
  send(daemon, raw(13), mode = "raw", block = 2000)
  recv(client, mode = "raw", block = 2000)
  task_msg <- raw(13)
  task_msg[1] <- as.raw(0x07)
  task_msg[5] <- as.raw(1L)
  send(client, task_msg, mode = "raw", block = 2000)
  task_recv <- recv(daemon, mode = "raw", block = 2000)
  test_type("raw", task_recv)
  send(daemon, raw(13), mode = "raw", block = 2000)
  result <- recv(client, mode = "raw", block = 2000)
  test_type("raw", result)
  sync_task <- raw(13)
  sync_task[1] <- as.raw(0x07)
  sync_task[4] <- as.raw(0x01)
  sync_task[5] <- as.raw(80L)
  send(client, sync_task, mode = "raw", block = 2000)
  sync_recv <- recv(daemon, mode = "raw", block = 2000)
  test_type("raw", sync_recv)
  send(daemon, raw(13), mode = "raw", block = 2000)
  recv(client, mode = "raw", block = 2000)
  daemon2 <- socket("poly", dial = url_poly)
  Sys.sleep(0.3)
  init_data2 <- recv(daemon2, mode = "raw", block = 2000)
  test_type("raw", init_data2)
  next_task <- raw(13)
  next_task[1] <- as.raw(0x07)
  next_task[5] <- as.raw(81L)
  send(client, next_task, mode = "raw", block = 2000)
  next_recv <- recv(daemon2, mode = "raw", block = 2000)
  test_type("raw", next_recv)
  send(daemon2, raw(13), mode = "raw", block = 2000)
  recv(client, mode = "raw", block = 2000)
  close(daemon2)
  Sys.sleep(0.1)
  post_sync <- raw(13)
  post_sync[1] <- as.raw(0x07)
  post_sync[5] <- as.raw(82L)
  send(client, post_sync, mode = "raw", block = 2000)
  post_recv <- recv(daemon, mode = "raw", block = 2000)
  test_type("raw", post_recv)
  mark_resp <- raw(13)
  mark_resp[1] <- as.raw(0x07)
  mark_resp[4] <- as.raw(0x01)
  send(daemon, mark_resp, mode = "raw", block = 2000)
  mark_res <- recv(client, mode = "raw", block = 2000)
  test_type("raw", mark_res)
  disc_sig <- recv(daemon, mode = "raw", block = 2000)
  test_equal(length(disc_sig), 0L)
  close(daemon)
  daemon3 <- socket("poly", dial = url_poly)
  Sys.sleep(0.3)
  recv(daemon3, mode = "raw", block = 2000)
  reset_task <- raw(13)
  reset_task[1] <- as.raw(0x07)
  reset_task[5] <- as.raw(90L)
  send(client, reset_task, mode = "raw", block = 2000)
  recv(daemon3, mode = "raw", block = 2000)
  close(daemon3)
  Sys.sleep(0.2)
  reset_result <- recv(client, mode = "raw", block = 2000)
  test_equal(length(reset_result), 10L)
  send(client, raw(8), mode = "raw", block = 2000)
  status_final <- recv(client, mode = "integer", block = 2000)
  test_equal(status_final[1L], 0L)
  close(client)
  Sys.sleep(0.5)
  unlink(script)
}

if (NOT_CRAN) {
  cert <- write_cert(cn = "127.0.0.1")
  certfile <- tempfile()
  cat(cert$server, file = certfile, sep = "\n")
  certfile <- gsub("\\", "/", certfile, fixed = TRUE)
  stream_code <- sprintf('
    library(nanonext)
    s <- stream(listen = "tcp://127.0.0.1:25555")
    msg <- recv(s, mode = "character", block = 2000)
    send(s, paste0("reply:", msg), block = 2000)
    msg2 <- recv(s, mode = "character", block = 2000)
    send(s, paste0("async:", msg2), block = 2000)
    Sys.sleep(0.1)
    close(s)
    tls <- tls_config(server = "%s")
    s <- stream(listen = "wss://127.0.0.1:25555/secure", tls = tls, textframes = TRUE)
    Sys.sleep(0.1)
    close(s)
  ', certfile)
  script <- tempfile(fileext = ".R")
  writeLines(stream_code, script)
  Rscript <- file.path(R.home("bin"), if (.Platform$OS.type == "windows") "Rscript.exe" else "Rscript")
  system2(Rscript, script, wait = FALSE, stdout = FALSE, stderr = FALSE)
  Sys.sleep(0.5)
  s <- tryCatch(stream(dial = "tcp://127.0.0.1:25555"), error = identity)
  if (is_nano(s)) {
    test_class("nanoStream", s)
    test_zero(send(s, "test", block = 2000))
    test_equal(recv(s, mode = "character"), "reply:test")
    test_class("sendAio", sa <- send_aio(s, "async_test", timeout = 2000))
    test_zero(call_aio(sa)$result)
    test_class("recvAio", ra <- recv_aio(s, mode = "character", timeout = 2000))
    test_equal(call_aio(ra)$data, "async:async_test")
    Sys.sleep(0.1)
    test_zero(close(s))
    test_equal(close(s), 7L)
    Sys.sleep(0.3)
    tls <- tls_config(client = cert$client)
    s <- tryCatch(stream(dial = "wss://127.0.0.1:25555/secure", tls = tls, textframes = TRUE), error = identity)
    if (is_nano(s)) {
      test_class("nanoStream", s)
      Sys.sleep(0.1)
      test_zero(close(s))
      test_equal(close(s), 7L)
    }
  }
  unlink(script)
  unlink(certfile)
}

test_error(http_server("http://127.0.0.1:29995", tls = "invalid"), "valid TLS")
fakeserver <- `class<-`("test", "nanoServer")
test_error(close(fakeserver), "valid HTTP Server")
test_class("list", suppressWarnings(handler_file("/bad", "/nonexistent/file.txt")))
test_error(handler_redirect("/bad", "/good", status = 999L), "301, 302, 303, 307, or 308")
fakestream_conn <- `class<-`("test", "nanoStreamConn")
test_print(fakestream_conn)

test_equal(format_sse("Hello"), "data: Hello\n\n")
test_equal(format_sse("Hello", event = "msg"), "event: msg\ndata: Hello\n\n")
test_equal(format_sse("Hello", id = "1"), "id: 1\ndata: Hello\n\n")
test_equal(format_sse("Hello", retry = 1000), "retry: 1000\ndata: Hello\n\n")
test_equal(format_sse("Line1\nLine2"), "data: Line1\ndata: Line2\n\n")
test_equal(format_sse("test", event = "e", id = "2", retry = 500), "event: e\nid: 2\nretry: 500\ndata: test\n\n")

if (later && NOT_CRAN) {
  test_error(http_server("http://127.0.0.1:0", handlers = list(list(type = 99L, path = "/"))), "Invalid argument")
  received_headers <- NULL
  test_class("nanoServer", srv <- http_server(
    url = "http://127.0.0.1:0",
    handlers = list(
      handler("/test", function(req) list(status = 200L, body = "OK")),
      handler("/api/data", function(req) {
        list(status = 200L, headers = c("Content-Type" = "application/json"), body = '{"value":42}')
      }),
      handler("/headers", function(req) {
        received_headers <<- req$headers
        list(status = 200L, body = paste(names(req$headers), collapse = ","))
      }),
      handler("/error", function(req) stop(simpleError("")))
    )
  ))
  test_print(srv)
  test_equal(attr(srv, "state"), "not started")
  test_zero(srv$start())
  test_equal(attr(srv, "state"), "started")
  base_url <- srv$url
  Sys.sleep(0.1)
  aio <- ncurl_aio(paste0(base_url, "/test"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)
  test_equal(aio$data, "OK")
  aio <- ncurl_aio(paste0(base_url, "/api/data"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)
  test_equal(aio$data, '{"value":42}')
  aio <- ncurl_aio(
    paste0(base_url, "/headers"),
    headers = c("X-Custom-Header" = "test123", "X-Another-Header" = "value456"),
    timeout = 2000
  )
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)
  test_true("X-Custom-Header" %in% names(received_headers))
  test_true("X-Another-Header" %in% names(received_headers))
  test_equal(received_headers[["X-Custom-Header"]], "test123")
  test_equal(received_headers[["X-Another-Header"]], "value456")
  aio <- ncurl_aio(paste0(base_url, "/error"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 500L)
  test_zero(srv$close())
}

if (later && NOT_CRAN) {
  msgs <- list()
  ws_conn <- NULL
  test_class("nanoServer", srv <- http_server(
    url = "http://127.0.0.1:0",
    handlers = list(
      handler("/", function(req) list(status = 200L, body = "index")),
      handler_ws(
        "/ws",
        on_message = function(ws, data) {
          msgs <<- c(msgs, list(data))
          ws$send(data)
        },
        on_open = function(ws) {
          ws_conn <<- ws
          msgs <<- c(msgs, list("open"))
        },
        on_close = function(ws) { msgs <<- c(msgs, list("close")) },
        textframes = TRUE
      )
    )
  ))
  test_zero(srv$start())
  base_url <- srv$url
  ws_url <- sub("^http", "ws", base_url)
  Sys.sleep(0.1)
  aio <- ncurl_aio(paste0(base_url, "/"), timeout = 2000)
  while (unresolved(aio)) later::run_now(1)
  test_equal(aio$status, 200L)
  test_equal(aio$data, "index")
  ws <- tryCatch(stream(dial = paste0(ws_url, "/ws"), textframes = TRUE), error = identity)
  if (is_nano(ws)) {
    while (is.null(ws_conn)) later::run_now(1)
    test_class("nanoWsConn", ws_conn)
    test_print(ws_conn)
    test_type("integer", ws_conn$id)
    test_type("closure", ws_conn$send)
    test_type("closure", ws_conn$close)
    test_null(ws_conn$nonexistent)
    test_zero(send(ws, "hello", block = 500))
    while (length(msgs) < 2L) later::run_now(1)
    reply <- recv(ws, block = 500, mode = "character")
    test_equal(reply, "hello")
    test_error(ws_conn$send(123L), "`data` must be raw or character")
    test_error(ws_conn$send(list(a = 1)), "`data` must be raw or character")
    test_zero(close(ws))
    for (i in 1:5) later::run_now(0.1)
    test_equal(msgs[[1]], "open")
    test_equal(msgs[[2]], "hello")
    test_equal(ws_conn$close(), 7L)
    test_equal(ws_conn$send("after close"), 7L)
    test_equal(ws_conn$send(charToRaw("raw after close")), 7L)
  }
  test_zero(srv$close())
  test_error(http_server(url = "http://127.0.0.1:0", handlers = list(
    handler_ws(paste0("/", strrep("x", 8180)), function(ws, data) ws$send(data))
  )), "Invalid argument")
}

if (later && NOT_CRAN) {
  auth_srv <- http_server(
    url = "http://127.0.0.1:0",
    handlers = list(handler_ws("/ws", function(ws, data) ws$send(data), on_open = function(ws) ws$close()))
  )
  test_zero(auth_srv$start())
  ws <- tryCatch(stream(dial = paste0(sub("^http", "ws", auth_srv$url), "/ws")), error = identity)
  if (is_nano(ws)) {
    later::run_now(1)
    close(ws)
  }
  test_zero(auth_srv$close())
}

if (later && NOT_CRAN) {
  gc_srv <- http_server(
    url = "http://127.0.0.1:0",
    handlers = list(
      handler("/gc", function(req) list(status = 200L, body = "gc test"))
    )
  )
  test_zero(gc_srv$start())
  Sys.sleep(0.1)
  rm(gc_srv)
  Sys.sleep(0.1)
  invisible(gc())
}

if (later && NOT_CRAN) {
  wss_cert <- write_cert(cn = "127.0.0.1")
  wss_tls_server <- tls_config(server = wss_cert$server)
  wss_tls_client <- tls_config(client = wss_cert$client)
  wss_msgs <- list()
  test_class("nanoServer", wss_srv <- http_server(
    url = "https://127.0.0.1:0",
    handlers = list(
      handler("/secure", function(req) list(status = 200L, body = "secure")),
      handler_ws(
        "/wss",
        on_message = function(ws, data) {
          wss_msgs <<- c(wss_msgs, list(data))
          ws$send(paste0("wss:", data))
        },
        on_open = function(ws) { wss_msgs <<- c(wss_msgs, list("wss_open")) },
        on_close = function(ws) { wss_msgs <<- c(wss_msgs, list("wss_close")) },
        textframes = TRUE
      )
    ),
    tls = wss_tls_server
  ))
  test_zero(wss_srv$start())
  wss_base_url <- wss_srv$url
  wss_ws_url <- sub("^https", "wss", wss_base_url)
  Sys.sleep(1L)
  wss_aio <- ncurl_aio(paste0(wss_base_url, "/secure"), tls = wss_tls_client, timeout = 2000)
  while (unresolved(wss_aio)) later::run_now(1)
  if (wss_aio$status == 200L) test_equal(wss_aio$data, "secure")
  wss_client <- tryCatch(stream(dial = paste0(wss_ws_url, "/wss"), tls = wss_tls_client, textframes = TRUE), error = identity)
  if (is_nano(wss_client)) {
    while (length(wss_msgs) < 1L) later::run_now(1)
    test_zero(send(wss_client, "secure_hello", block = 500))
    while (length(wss_msgs) < 2L) later::run_now(1)
    wss_reply <- recv(wss_client, block = 500, mode = "character")
    test_equal(wss_reply, "wss:secure_hello")
    test_zero(close(wss_client))
    later::run_now(1)
    test_equal(wss_msgs[[1]], "wss_open")
    test_equal(wss_msgs[[2]], "secure_hello")
  }
  test_zero(wss_srv$close())
}

# Test multiple WebSocket endpoints and concurrent connections
if (later && NOT_CRAN) {
  echo_msgs <- list()
  upper_msgs <- list()
  conn_ids <- c()
  test_class("nanoServer", multi_ws_srv <- http_server(
    url = "http://127.0.0.1:0",
    handlers = list(
      handler_ws("/echo", function(ws, data) {
        echo_msgs <<- c(echo_msgs, list(data))
        ws$send(data)
      }),
      handler_ws("/upper", function(ws, data) {
        upper_msgs <<- c(upper_msgs, list(data))
        ws$send(toupper(data))
      }, on_open = function(ws) {
        conn_ids <<- c(conn_ids, ws$id)
      }, textframes = TRUE)
    )
  ))
  test_zero(multi_ws_srv$start())
  test_zero(multi_ws_srv$start())
  base_url <- multi_ws_srv$url
  ws_url <- sub("^http", "ws", base_url)
  Sys.sleep(0.1)

  ws_echo <- tryCatch(stream(dial = paste0(ws_url, "/echo")), error = identity)
  if (is_nano(ws_echo)) {
    later::run_now(1)
    test_zero(send(ws_echo, charToRaw("binary_test"), block = 500))
    while (length(echo_msgs) < 1L) later::run_now(1)
    echo_reply <- recv(ws_echo, block = 500, mode = "raw")
    test_equal(rawToChar(echo_reply), "binary_test")
    test_zero(close(ws_echo))
    later::run_now(1)
  }

  ws_upper1 <- tryCatch(stream(dial = paste0(ws_url, "/upper"), textframes = TRUE), error = identity)
  ws_upper2 <- tryCatch(stream(dial = paste0(ws_url, "/upper"), textframes = TRUE), error = identity)
  if (is_nano(ws_upper1) && is_nano(ws_upper2)) {
    while (length(conn_ids) < 2L) later::run_now(1)
    test_equal(length(conn_ids), 2L)
    test_true(conn_ids[1] != conn_ids[2])

    test_zero(send(ws_upper1, "hello", block = 500))
    test_zero(send(ws_upper2, "world", block = 500))
    while (length(upper_msgs) < 2L) later::run_now(1)
    upper_reply1 <- recv(ws_upper1, block = 500, mode = "character")
    upper_reply2 <- recv(ws_upper2, block = 500, mode = "character")
    test_equal(upper_reply1, "HELLO")
    test_equal(upper_reply2, "WORLD")
    test_zero(close(ws_upper1))
    test_zero(close(ws_upper2))
    later::run_now(1)
  }

  test_zero(multi_ws_srv$close())
  test_error(multi_ws_srv$start(), "valid HTTP Server")
}

# Test static handlers, redirects, and prefix parameter
if (later && NOT_CRAN) {
  test_class("list", suppressWarnings(handler_directory("/bad", "/nonexistent/directory")))

  static_test_dir <- tempfile()
  dir.create(static_test_dir)
  writeLines("Hello from file", file.path(static_test_dir, "test.txt"))
  writeLines("<html><body>Index</body></html>", file.path(static_test_dir, "index.html"))

  test_class("nanoServer", static_srv <- http_server(
    url = "http://127.0.0.1:0",
    handlers = list(
      handler_file("/single.txt", file.path(static_test_dir, "test.txt")),
      handler_file("/tree-file", file.path(static_test_dir, "test.txt"), prefix = TRUE),
      handler_directory("/files", static_test_dir),
      handler_inline("/inline", "Inline content", content_type = "text/plain"),
      handler_inline("/tree-inline", "tree inline", content_type = "text/plain", prefix = TRUE),
      handler_inline("/binary", as.raw(c(0x89, 0x50, 0x4e, 0x47))),
      handler_redirect("/r301", "/single.txt", status = 301L),
      handler_redirect("/r302", "/single.txt", status = 302L),
      handler_redirect("/r303", "/single.txt", status = 303L),
      handler_redirect("/r307", "/single.txt", status = 307L),
      handler_redirect("/r308", "/single.txt", status = 308L),
      handler_redirect("/tree-redir", "/single.txt", status = 302L, prefix = TRUE)
    )
  ))
  test_zero(static_srv$start())
  base_url <- static_srv$url
  Sys.sleep(0.1)

  aio <- ncurl_aio(paste0(base_url, "/single.txt"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)
  test_equal(trimws(aio$data), "Hello from file")

  aio <- ncurl_aio(paste0(base_url, "/tree-file/extra"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)

  aio <- ncurl_aio(paste0(base_url, "/files/test.txt"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)

  aio <- ncurl_aio(paste0(base_url, "/inline"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)
  test_equal(aio$data, "Inline content")

  aio <- ncurl_aio(paste0(base_url, "/tree-inline/extra"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)
  test_equal(aio$data, "tree inline")

  aio <- ncurl_aio(paste0(base_url, "/binary"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)

  for (code in c(301L, 302L, 303L, 307L, 308L)) {
    aio <- ncurl_aio(paste0(base_url, "/r", code), timeout = 2000)
    for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
    test_equal(aio$status, code)
  }

  aio <- ncurl_aio(paste0(base_url, "/tree-redir/extra"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 302L)

  test_zero(static_srv$close())
  unlink(static_test_dir, recursive = TRUE)
}

# Test handler features: prefix, method, raw body, default status
if (later && NOT_CRAN) {
  test_class("nanoServer", handler_srv <- http_server(
    url = "http://127.0.0.1:0",
    handlers = list(
      handler("/api", function(req) list(status = 200L, body = paste("path:", req$uri)), prefix = TRUE),
      handler("/any", function(req) list(status = 200L, body = req$method), method = "*"),
      handler("/put", function(req) list(status = 200L, body = "PUT OK"), method = "PUT"),
      handler("/delete", function(req) list(status = 200L, body = "DELETE OK"), method = "DELETE"),
      handler("/raw", function(req) list(status = 200L, body = charToRaw("raw response"))),
      handler("/default-status", function(req) list(body = "no status")),
      handler("/no-body", function(req) list(status = 204L))
    )
  ))
  test_zero(handler_srv$start())
  base_url <- handler_srv$url
  Sys.sleep(0.1)

  aio <- ncurl_aio(paste0(base_url, "/api/users/123"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)
  test_equal(aio$data, "path: /api/users/123")

  aio <- ncurl_aio(paste0(base_url, "/any"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)

  aio <- ncurl_aio(paste0(base_url, "/any"), method = "POST", timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)

  aio <- ncurl_aio(paste0(base_url, "/put"), method = "PUT", timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)
  test_equal(aio$data, "PUT OK")

  aio <- ncurl_aio(paste0(base_url, "/delete"), method = "DELETE", timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)
  test_equal(aio$data, "DELETE OK")

  aio <- ncurl_aio(paste0(base_url, "/raw"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)
  test_equal(aio$data, "raw response")

  aio <- ncurl_aio(paste0(base_url, "/default-status"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 200L)
  test_equal(aio$data, "no status")

  aio <- ncurl_aio(paste0(base_url, "/no-body"), timeout = 2000)
  for (i in 1:20) { later::run_now(0.1); if (!unresolved(aio)) break }
  test_equal(aio$status, 204L)

  test_zero(handler_srv$close())
}

if (later && NOT_CRAN) {
  stream_conn <- NULL
  stream_closed <- FALSE
  test_class("nanoServer", sse_srv <- http_server(
    url = "http://127.0.0.1:0",
    handlers = list(
      handler_stream(
        "/events",
        on_request = function(conn, req) {
          stream_conn <<- conn
          conn$set_status(200L)
          conn$set_header("Content-Type", "text/event-stream")
          conn$set_header("Cache-Control", "no-cache")
          conn$send(format_sse(data = "connected"))
        },
        on_close = function(conn) {
          stream_closed <<- TRUE
        }
      )
    )
  ))
  test_zero(sse_srv$start())
  base_url <- sse_srv$url
  Sys.sleep(0.1)

  sse_client <- tryCatch(stream(dial = paste0("tcp://", sub("^http://", "", base_url), "/events")), error = identity)
  if (is_nano(sse_client)) {

    http_req <- "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n"
    test_zero(send(sse_client, http_req, block = 500))
    while (is.null(stream_conn)) later::run_now(1)

    test_class("nanoStreamConn", stream_conn)
    test_print(stream_conn)
    test_type("integer", stream_conn$id)
    test_type("closure", stream_conn$send)
    test_type("closure", stream_conn$close)
    test_type("closure", stream_conn$set_status)
    test_type("closure", stream_conn$set_header)
    test_null(stream_conn$nonexistent)

    test_error(stream_conn$set_status(201L), "after headers have been sent")
    test_error(stream_conn$set_header("X-Test", "value"), "after headers have been sent")

    test_zero(stream_conn$send(format_sse(data = "update")))

    test_error(stream_conn$send(123L), "`data` must be raw or character")
    test_error(stream_conn$send(list()), "`data` must be raw or character")

    test_zero(stream_conn$close())
    while (!stream_closed) later::run_now(1)
    test_true(stream_closed)

    test_error(stream_conn$send("after close"), "valid connection")
    test_class("errorValue", stream_conn$close())

    close(sse_client)
  }
  test_zero(sse_srv$close())
}

if (later && NOT_CRAN) {
  conns <- list()
  test_class("nanoServer", broadcast_srv <- http_server(
    url = "http://127.0.0.1:0",
    handlers = list(
      handler_stream(
        "/notify",
        on_request = function(conn, req) {
          conn$set_header("Content-Type", "text/event-stream")
          conns[[as.character(conn$id)]] <<- conn
          conn$send(format_sse(data = "subscribed"))
        }
      )
    )
  ))
  test_zero(broadcast_srv$start())
  base_url <- broadcast_srv$url
  Sys.sleep(0.1)

  client1 <- tryCatch(stream(dial = paste0("tcp://", sub("^http://", "", base_url), "/notify")), error = identity)
  client2 <- tryCatch(stream(dial = paste0("tcp://", sub("^http://", "", base_url), "/notify")), error = identity)
  client3 <- tryCatch(stream(dial = paste0("tcp://", sub("^http://", "", base_url), "/notify")), error = identity)

  if (is_nano(client1) && is_nano(client2) && is_nano(client3)) {
    http_req <- "GET /notify HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n"
    send(client1, http_req, block = 500)
    send(client2, http_req, block = 500)
    send(client3, http_req, block = 500)
    while (length(conns) < 3L) later::run_now(1)

    test_equal(length(conns), 3L)

    conn1 <- conns[[1L]]
    test_type("closure", conn1$broadcast)
    results <- conn1$broadcast(format_sse(data = "news"))
    test_equal(length(results), 3L)
    test_true(all(results == 0L))

    test_error(conn1$broadcast(123L), "`data` must be raw or character")

    results <- conn1$broadcast(charToRaw("raw broadcast"))
    test_equal(length(results), 3L)
    test_true(all(results == 0L))

    close(client1)
    close(client2)
    close(client3)
    for (i in 1:5) later::run_now(0.1)
  }

  test_zero(broadcast_srv$close())
}

if (later && NOT_CRAN) {
  received_methods <- character()
  test_class("nanoServer", method_srv <- http_server(
    url = "http://127.0.0.1:0",
    handlers = list(
      handler_stream(
        "/stream",
        on_request = function(conn, req) {
          received_methods <<- c(received_methods, req$method)
          conn$set_header("Content-Type", "text/plain")
          conn$send(paste0("method:", req$method))
          conn$close()
        }
      )
    )
  ))
  test_zero(method_srv$start())
  base_url <- method_srv$url
  Sys.sleep(0.1)

  get_aio <- ncurl_aio(paste0(base_url, "/stream"))
  while (unresolved(get_aio)) later::run_now(1)
  test_equal(call_aio(get_aio)$status, 200L)

  post_aio <- ncurl_aio(paste0(base_url, "/stream"), method = "POST", data = "test")
  while (unresolved(post_aio)) later::run_now(1)
  test_equal(call_aio(post_aio)$status, 200L)

  test_true("GET" %in% received_methods)
  test_true("POST" %in% received_methods)

  test_zero(method_srv$close())
}

if (!interactive() && NOT_CRAN) {
  test_class("conditionVariable", cv <- cv())
  f <- file("stdin", open = "r")
  test_true(is_nano(reader <- read_stdin()))
  test_zero(pipe_notify(reader, cv, remove = TRUE, flag = TRUE))
  test_true(is_aio(r <- recv_aio(reader, mode = "raw", cv = cv)))
  close(f)
  test_false(wait(cv))
  test_zero(close(reader))
  test_equal(collect_aio(r), 7L)
}

if (Sys.info()[["sysname"]] == "Linux") {
  rm(list = ls())
  invisible(gc())
  .Call(nanonext:::rnng_fini_priors)
  Sys.sleep(1L)
  .Call(nanonext:::rnng_fini)
  invisible()
}
