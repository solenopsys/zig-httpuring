const std = @import("std");

const HttpRequest = @import("picozig").HttpRequest;
const HttpResponse = @import("picozig").HttpResponse;
const Allocator = std.mem.Allocator;

const HandlerError = error{
    OutOfMemory,
    InvalidInput,
};

pub const ProtocolHandler = struct {
    pathPrefix: []const u8,
    method: []const u8,
    handleFn: *const fn (request: HttpRequest, allocator: Allocator) error{OutOfMemory}![]const u8,
};
pub const DataHandler = struct {
    processFn: fn (allocator: std.mem.Allocator, data: []const u8) HandlerError![]const u8,
};

// Константа для включения/отключения логирования
pub const enable_logging = true;

// Функция логирования, которая проверяет константу
pub fn log(comptime fmt: []const u8, args: anytype) void {
    if (enable_logging) {
        std.debug.print(fmt, args);
    }
}
