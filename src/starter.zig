const std = @import("std");
const Thread = std.Thread;

const HttpProcessor = @import("./http-processor.zig").HttpProcessor;
const DataHandler = @import("./types.zig").DataHandler;
const ServerConfig = @import("./http-server.zig").ServerConfig;
const startServer = @import("./http-server.zig").startServer;

pub fn start(handler: DataHandler) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // Разбор аргументов командной строки
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var port: u16 = 8080;
    var secure = false;
    var cert_file: ?[]const u8 = null;
    var key_file: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i < args.len) {
                port = try std.fmt.parseInt(u16, args[i], 10);
            }
        } else if (std.mem.eql(u8, arg, "--secure")) {
            secure = true;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            i += 1;
            if (i < args.len) {
                cert_file = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--key")) {
            i += 1;
            if (i < args.len) {
                key_file = args[i];
            }
        }
    }

    // Если включен HTTPS, но не указаны пути к сертификату или ключу,
    // используем пути по умолчанию
    if (secure and (cert_file == null or key_file == null)) {
        if (cert_file == null) cert_file = "server.crt";
        if (key_file == null) key_file = "server.key";

        std.debug.print("Используются файлы по умолчанию: сертификат={s}, ключ={s}\n", .{ cert_file.?, key_file.? });
    }

    // Выбор числа воркеров на основе количества процессоров
    const num_cpus = try Thread.getCpuCount();
    const num_workers = if (num_cpus > 1) num_cpus else 2;

    const server_config = ServerConfig{
        .port = port,
        .num_workers = num_workers,
        .secure = secure,
        .cert_file = cert_file,
        .key_file = key_file,
    };

    try startServer(allocator, server_config, handler);
}
