const std = @import("std");
const net = std.net;
const posix = std.posix;
const linux = std.os.linux;
const Thread = std.Thread;
const Allocator = std.mem.Allocator;
const fs = std.fs;
const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/crypto.h");
});

const log = @import("./types.zig").log;

const DataHandler = @import("types.zig").DataHandler;

pub const ServerConfig = struct {
    port: u16,
    num_workers: usize,
    secure: bool = false,
    cert_file: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
};

const SSLContext = struct {
    ctx: ?*c.SSL_CTX = null,

    pub fn init(cert_file: []const u8, key_file: []const u8) !SSLContext {
        // Инициализация BoringSSL
        _ = c.OPENSSL_init_ssl(@as(u64, 0), null);
        _ = c.OPENSSL_init_crypto(@as(u64, 0), null);

        // Создание SSL контекста
        const method = c.TLS_method();
        if (method == null) return error.SSLMethodFailed;

        const ctx = c.SSL_CTX_new(method);
        if (ctx == null) return error.SSLContextCreationFailed;
        errdefer c.SSL_CTX_free(ctx);

        // Установка сертификата и приватного ключа
        if (c.SSL_CTX_use_certificate_file(ctx, @ptrCast(cert_file.ptr), c.SSL_FILETYPE_PEM) <= 0) {
            log("Ошибка при загрузке сертификата: {s}\n", .{cert_file});
            return error.CertificateLoadFailed;
        }

        if (c.SSL_CTX_use_PrivateKey_file(ctx, @ptrCast(key_file.ptr), c.SSL_FILETYPE_PEM) <= 0) {
            log("Ошибка при загрузке приватного ключа: {s}\n", .{key_file});
            return error.PrivateKeyLoadFailed;
        }

        // Проверка соответствия ключа и сертификата
        if (c.SSL_CTX_check_private_key(ctx) == 0) {
            log("Приватный ключ не соответствует сертификату\n", .{});
            return error.KeyCertificateMismatch;
        }

        return SSLContext{ .ctx = ctx };
    }

    pub fn deinit(self: *SSLContext) void {
        if (self.ctx != null) {
            c.SSL_CTX_free(self.ctx);
            self.ctx = null;
        }
    }
};

const LocalBufferPool = struct {
    allocator: Allocator,
    buffers: std.ArrayList([]u8),

    pub fn init(allocator: Allocator, initial_size: usize, buffer_size: usize) !LocalBufferPool {
        var buffers = std.ArrayList([]u8).init(allocator);
        for (0..initial_size) |_| {
            const buffer = try allocator.alloc(u8, buffer_size);
            try buffers.append(buffer);
        }
        return LocalBufferPool{ .allocator = allocator, .buffers = buffers };
    }

    pub fn deinit(self: *LocalBufferPool) void {
        for (self.buffers.items) |buffer| {
            self.allocator.free(buffer);
        }
        self.buffers.deinit();
    }

    pub fn getBuffer(self: *LocalBufferPool, buffer_size: usize) ![]u8 {
        if (self.buffers.items.len > 0) {
            return self.buffers.pop() orelse error.BufferNotAvailable;
        }
        return try self.allocator.alloc(u8, buffer_size);
    }

    pub fn returnBuffer(self: *LocalBufferPool, buffer: []u8) !void {
        try self.buffers.append(buffer);
    }
};

const Client = struct {
    socket: posix.fd_t,
    buffer: []u8,
    data: std.ArrayList(u8),
    is_complete: bool,
    keep_alive: bool,
    ssl: ?*c.SSL = null,
    is_secure: bool = false,

    pub fn init(socket: posix.fd_t, buffer: []u8, allocator: Allocator, is_secure: bool, ssl_ctx: ?*c.SSL_CTX) Client {
        var client = Client{
            .socket = socket,
            .buffer = buffer,
            .data = std.ArrayList(u8).init(allocator),
            .is_complete = false,
            .keep_alive = true,
            .is_secure = is_secure,
        };

        if (is_secure and ssl_ctx != null) {
            client.ssl = c.SSL_new(ssl_ctx);
            if (client.ssl != null) {
                _ = c.SSL_set_fd(client.ssl, @intCast(socket));
            }
        }

        return client;
    }

    pub fn deinit(self: *Client) void {
        self.data.deinit();
        if (self.ssl != null) {
            c.SSL_free(self.ssl);
            self.ssl = null;
        }
    }

    pub fn reset(self: *Client) void {
        self.data.clearRetainingCapacity();
        self.is_complete = false;
    }

    pub fn doSSLAccept(self: *Client) !bool {
        if (!self.is_secure or self.ssl == null) return true;

        const result = c.SSL_accept(self.ssl);
        if (result <= 0) {
            const error_code = c.SSL_get_error(self.ssl, result);
            if (error_code == c.SSL_ERROR_WANT_READ or error_code == c.SSL_ERROR_WANT_WRITE) {
                // Нужно повторить позже
                return false;
            }
            // Фатальная ошибка
            log("SSL_accept ошибка: {d}\n", .{error_code});
            return error.SSLAcceptFailed;
        }
        return true;
    }

    pub fn readData(self: *Client, max_size: usize) !?usize {
        if (self.is_secure and self.ssl != null) {
            // Чтение через SSL
            const bytes_read = c.SSL_read(self.ssl, @ptrCast(self.buffer.ptr), @intCast(max_size));
            if (bytes_read <= 0) {
                const error_code = c.SSL_get_error(self.ssl, bytes_read);
                if (error_code == c.SSL_ERROR_WANT_READ or error_code == c.SSL_ERROR_WANT_WRITE) {
                    // Нужно повторить позже
                    return null;
                }
                if (error_code == c.SSL_ERROR_ZERO_RETURN) {
                    // Соединение закрыто корректно
                    return 0;
                }
                // Другая ошибка
                log("SSL_read ошибка: {d}\n", .{error_code});
                return error.SSLReadFailed;
            }
            return @intCast(bytes_read);
        } else {
            // Обычное чтение
            const bytes_read = try posix.read(self.socket, self.buffer[0..max_size]);
            return bytes_read;
        }
    }

    pub fn writeData(self: *Client, data: []const u8) !usize {
        if (self.is_secure and self.ssl != null) {
            // Запись через SSL
            const bytes_written = c.SSL_write(self.ssl, @ptrCast(data.ptr), @intCast(data.len));
            if (bytes_written <= 0) {
                const error_code = c.SSL_get_error(self.ssl, bytes_written);
                if (error_code == c.SSL_ERROR_WANT_WRITE or error_code == c.SSL_ERROR_WANT_READ) {
                    // Нужно повторить позже
                    return 0;
                }
                // Другая ошибка
                log("SSL_write ошибка: {d}\n", .{error_code});
                return error.SSLWriteFailed;
            }
            return @intCast(bytes_written);
        } else {
            // Обычная запись
            return try posix.write(self.socket, data);
        }
    }
};

// Сигнатура poll_add: fn poll_add(self: *IoUring, user_data: u64, fd: i32, poll_mask: u32) !void
const Worker = struct {
    id: usize,
    allocator: Allocator,
    server_socket: posix.fd_t,
    ring: linux.IoUring,
    clients: std.AutoHashMap(u64, Client),
    next_client_id: u64,
    buffer_pool: LocalBufferPool,
    buffer_size: usize,
    is_secure: bool,
    ssl_ctx: ?*c.SSL_CTX,
    handler: DataHandler,

    pub fn init(allocator: Allocator, handler: DataHandler, id: usize, port: u16, buffer_size: usize, initial_pool_size: usize, is_secure: bool, ssl_ctx: ?*c.SSL_CTX) !Worker {
        const server_socket = try createServerSocket(port);
        var ring_params = std.mem.zeroes(linux.io_uring_params);

        const ring_size: u13 = 4096;
        const ring = try linux.IoUring.init_params(ring_size, &ring_params);
        const buffer_pool = try LocalBufferPool.init(allocator, initial_pool_size, buffer_size);

        return Worker{
            .id = id,
            .allocator = allocator,
            .server_socket = server_socket,
            .ring = ring,
            .clients = std.AutoHashMap(u64, Client).init(allocator),
            .next_client_id = 1,
            .buffer_pool = buffer_pool,
            .buffer_size = buffer_size,
            .is_secure = is_secure,
            .ssl_ctx = ssl_ctx,
            .handler = handler,
        };
    }

    pub fn deinit(self: *Worker) void {
        var it = self.clients.iterator();
        while (it.next()) |entry| {
            posix.close(entry.value_ptr.socket);
            entry.value_ptr.deinit();
            self.buffer_pool.returnBuffer(entry.value_ptr.buffer) catch {};
        }
        self.clients.deinit();
        self.ring.deinit();
        self.buffer_pool.deinit();
        posix.close(self.server_socket);
    }

    pub fn run(self: *Worker) !void {
        log("Воркер {d} запущен (secure: {any})\n", .{ self.id, self.is_secure });
        const accept_user_data: u64 = 0;
        _ = try self.ring.accept(accept_user_data, self.server_socket, null, null, 0);

        while (true) {
            const submitted = self.ring.submit_and_wait(1) catch |err| {
                log("Воркер {d}: Ошибка submit_and_wait: {any}\n", .{ self.id, err });
                continue;
            };
            _ = submitted;

            while (self.ring.cq_ready() > 0) {
                const cqe = self.ring.copy_cqe() catch |err| {
                    log("Воркер {d}: Ошибка copy_cqe: {any}\n", .{ self.id, err });
                    continue;
                };

                if (cqe.user_data == 0) {
                    self.handleAccept(cqe.res) catch |err| {
                        log("Воркер {d}: Ошибка handleAccept: {any}\n", .{ self.id, err });
                    };
                    _ = self.ring.accept(accept_user_data, self.server_socket, null, null, 0) catch |err| {
                        log("Воркер {d}: Ошибка добавления accept: {any}\n", .{ self.id, err });
                    };
                } else {
                    // Проверяем, какая операция была завершена
                    const op_type = cqe.user_data >> 32;
                    const client_id = cqe.user_data & 0xFFFFFFFF;

                    if (op_type == 1) { // Операция чтения
                        self.handleClientRead(client_id, cqe.res) catch |err| {
                            log("Воркер {d}: Ошибка handleClientRead: {any}\n", .{ self.id, err });
                        };
                    } else if (op_type == 2) { // Операция записи
                        self.handleClientWrite(client_id, cqe.res) catch |err| {
                            log("Воркер {d}: Ошибка handleClientWrite: {any}\n", .{ self.id, err });
                        };
                    } else if (op_type == 3) { // SSL Handshake
                        self.handleSSLHandshake(client_id) catch |err| {
                            log("Воркер {d}: Ошибка handleSSLHandshake: {any}\n", .{ self.id, err });
                        };
                    }
                }
            }
        }
    }

    fn handleAccept(self: *Worker, result: i32) !void {
        if (result < 0) {
            log("Воркер {d}: Ошибка accept: {d}\n", .{ self.id, result });
            return;
        }

        const client_socket: i32 = @intCast(result);
        const buffer = try self.buffer_pool.getBuffer(self.buffer_size);

        const client_id = self.next_client_id & 0xFFFFFFFF;
        self.next_client_id += 1;

        const client = Client.init(client_socket, buffer, self.allocator, self.is_secure, self.ssl_ctx);
        try self.clients.put(client_id, client);

        if (self.is_secure) {
            // Начинаем SSL handshake
            const ssl_handshake_user_data = (3 << 32) | client_id;
            _ = self.ring.poll_add(ssl_handshake_user_data, @intCast(client_socket), @intCast(linux.POLL.IN)) catch |err| {
                log("Воркер {d}: Ошибка добавления SSL handshake: {any}\n", .{ self.id, err });
                self.closeClient(client_id);
            };
        } else {
            // Для обычного HTTP сразу начинаем чтение
            const read_user_data = (1 << 32) | client_id;
            _ = self.ring.read(read_user_data, client_socket, .{ .buffer = buffer }, 0) catch |err| {
                log("Воркер {d}: Ошибка добавления read: {any}\n", .{ self.id, err });
                self.closeClient(client_id);
            };
        }
    }

    fn handleSSLHandshake(self: *Worker, client_id: u64) !void {
        const client = self.clients.getPtr(client_id) orelse return;

        const success = client.doSSLAccept() catch {
            self.closeClient(client_id);
            return;
        };

        if (success) {
            // SSL handshake успешно завершен, начинаем чтение
            const read_user_data = (1 << 32) | client_id;
            _ = self.ring.poll_add(read_user_data, @intCast(client.socket), @intCast(linux.POLL.IN)) catch |err| {
                log("Воркер {d}: Ошибка добавления read после SSL handshake: {any}\n", .{ self.id, err });
                self.closeClient(client_id);
            };
        } else {
            // Handshake еще не завершен, продолжаем ждать
            const ssl_handshake_user_data = (3 << 32) | client_id;
            _ = self.ring.poll_add(ssl_handshake_user_data, @intCast(client.socket), @intCast(linux.POLL.IN | linux.POLL.OUT)) catch |err| {
                log("Воркер {d}: Ошибка добавления повторного SSL handshake: {any}\n", .{ self.id, err });
                self.closeClient(client_id);
            };
        }
    }

    fn handleClientRead(self: *Worker, client_id: u64, result: i32) !void {
        const client = self.clients.getPtr(client_id) orelse return;

        if (result <= 0 and !client.is_secure) {
            log("Воркер {d}: Клиент {d} закрыл соединение или ошибка чтения: {d}\n", .{ self.id, client_id, result });
            self.closeClient(client_id);
            return;
        }

        // Для SSL соединений result просто указывает на готовность сокета,
        // мы должны вызвать SSL_read отдельно
        var bytes_read: ?usize = null;
        if (client.is_secure) {
            bytes_read = client.readData(client.buffer.len) catch {
                self.closeClient(client_id);
                return;
            };

            if (bytes_read == null) {
                // Нужно повторить чтение позже
                const read_user_data = (1 << 32) | client_id;
                _ = try self.ring.poll_add(read_user_data, @intCast(client.socket), @intCast(linux.POLL.IN));
                return;
            }

            if (bytes_read.? == 0) {
                // Соединение закрыто
                self.closeClient(client_id);
                return;
            }
        } else {
            bytes_read = @intCast(result);
        }

        try client.data.appendSlice(client.buffer[0..bytes_read.?]);

        // Проверяем, имеем ли мы полный HTTP запрос
        if (!client.is_complete) {
            if (std.mem.indexOf(u8, client.data.items, "\r\n\r\n")) |_| {
                client.is_complete = true;
            } else {
                // Если запрос не полный, читаем дальше
                if (client.is_secure) {
                    const read_user_data = (1 << 32) | client_id;
                    _ = try self.ring.poll_add(read_user_data, @intCast(client.socket), @intCast(linux.POLL.IN));
                } else {
                    const read_user_data = (1 << 32) | client_id;
                    _ = try self.ring.read(read_user_data, client.socket, .{ .buffer = client.buffer }, 0);
                }
                return;
            }
        }

        const request = client.data.items;

        // Определяем, нужно ли поддерживать соединение
        client.keep_alive = true;
        if (std.mem.indexOf(u8, request, "Connection: close") != null) {
            client.keep_alive = false;
        } else if (std.mem.indexOf(u8, request, "HTTP/1.0") != null) {
            // HTTP/1.0 не поддерживает keep-alive по умолчанию
            if (std.mem.indexOf(u8, request, "Connection: keep-alive") == null) {
                client.keep_alive = false;
            }
        }

        const response = try self.handler.processFn(self.allocator, request);
        // = try httpHandler(self.allocator, request);

        // Для SSL соединений используем poll_add для записи
        if (client.is_secure) {
            // Сохраняем ответ для записи в handleClientWrite
            const response_copy = try self.allocator.dupe(u8, response);
            client.data.clearRetainingCapacity();
            try client.data.appendSlice(response_copy);
            self.allocator.free(response_copy);

            const write_user_data = (2 << 32) | client_id;
            _ = try self.ring.poll_add(write_user_data, @intCast(client.socket), @intCast(linux.POLL.OUT));
        } else {
            // Отправляем ответ
            const write_user_data = (2 << 32) | client_id;
            _ = try self.ring.write(write_user_data, client.socket, response, 0);
        }
    }

    fn handleClientWrite(self: *Worker, client_id: u64, result: i32) !void {
        const client = self.clients.getPtr(client_id) orelse return;

        if (result < 0 and !client.is_secure) {
            log("Воркер {d}: Ошибка записи для клиента {d}: {d}\n", .{ self.id, client_id, result });
            self.closeClient(client_id);
            return;
        }

        // Для SSL соединений result просто указывает на готовность сокета,
        // мы должны вызвать SSL_write отдельно
        if (client.is_secure) {
            const bytes_written = client.writeData(client.data.items) catch {
                self.closeClient(client_id);
                return;
            };

            if (bytes_written == 0) {
                // Нужно повторить запись позже
                const write_user_data = (2 << 32) | client_id;
                _ = try self.ring.poll_add(write_user_data, @intCast(client.socket), @intCast(linux.POLL.OUT));
                return;
            }

            // Если отправили не все данные, обновляем буфер и продолжаем отправку
            if (bytes_written < client.data.items.len) {
                client.data.replaceRange(0, bytes_written, &.{}) catch {
                    self.closeClient(client_id);
                    return;
                };

                const write_user_data = (2 << 32) | client_id;
                _ = try self.ring.poll_add(write_user_data, @intCast(client.socket), @intCast(linux.POLL.OUT));
                return;
            }
        }

        // Если клиент не хочет Keep-Alive, закрываем соединение
        if (!client.keep_alive) {
            self.closeClient(client_id);
            return;
        }

        // Сбрасываем состояние клиента для нового запроса
        client.reset();

        // Подготавливаем новое чтение
        if (client.is_secure) {
            const read_user_data = (1 << 32) | client_id;
            _ = try self.ring.poll_add(read_user_data, @intCast(client.socket), @intCast(linux.POLL.IN));
        } else {
            const read_user_data = (1 << 32) | client_id;
            _ = try self.ring.read(read_user_data, client.socket, .{ .buffer = client.buffer }, 0);
        }
    }

    fn closeClient(self: *Worker, client_id: u64) void {
        const client_entry = self.clients.fetchRemove(client_id) orelse return;
        var client = client_entry.value;

        posix.close(client.socket);
        client.deinit();
        self.buffer_pool.returnBuffer(client.buffer) catch {
            log("Воркер {d}: Ошибка возврата буфера для клиента {d}\n", .{ self.id, client_id });
        };
    }
};

fn createServerSocket(port: u16) !posix.fd_t {
    const socket = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    errdefer posix.close(socket);

    const yes: i32 = 1;
    try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes));
    try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&yes));

    const address = net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
    try posix.bind(socket, &address.any, address.getOsSockLen());
    try posix.listen(socket, 1024);

    return socket;
}

pub fn startServer(allocator: Allocator, config: ServerConfig, handler: DataHandler) !void {
    const buffer_size = 8192; // Увеличил размер буфера
    const initial_pool_size = 256; // Увеличил размер пула буферов

    var ssl_context: ?SSLContext = null;
    defer if (ssl_context) |*ctx| ctx.deinit();

    var ssl_ctx: ?*c.SSL_CTX = null;
    if (config.secure) {
        if (config.cert_file == null or config.key_file == null) {
            return error.MissingCertificateOrKey;
        }
        ssl_context = try SSLContext.init(config.cert_file.?, config.key_file.?);
        ssl_ctx = ssl_context.?.ctx;
    }

    var workers = try allocator.alloc(Worker, config.num_workers);
    defer {
        for (workers) |*worker| {
            worker.deinit();
        }
        allocator.free(workers);
    }

    const threads = try allocator.alloc(Thread, config.num_workers);
    defer allocator.free(threads);

    for (workers, 0..) |*worker, i| {
        worker.* = try Worker.init(allocator, handler, i, config.port, buffer_size, initial_pool_size, config.secure, ssl_ctx);
    }

    for (threads, 0..) |*thread, i| {
        thread.* = try Thread.spawn(.{}, workerMain, .{&workers[i]});
    }

    // Выводим информацию о запуске один раз
    if (config.secure) {
        std.debug.print("HTTPS сервер запущен на порту {d}\n", .{config.port});
    } else {
        std.debug.print("HTTP сервер запущен на порту {d}\n", .{config.port});
    }

    for (threads) |thread| {
        thread.join();
    }
}

fn workerMain(worker: *Worker) void {
    worker.run() catch |err| {
        log("Ошибка в воркере {d}: {any}\n", .{ worker.id, err });
    };
}
