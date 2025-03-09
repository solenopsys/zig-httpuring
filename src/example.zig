const std = @import("std");

const http = @import("./starter.zig");
const DataHandler = @import("./types.zig").DataHandler;
const httpHandler = @import("./http-handler.zig").httpHandler;

pub fn main() !void {
    const handler = DataHandler{
        .processFn = httpHandler,
    };
    http.start(handler) catch |err| {
        std.debug.print("Ошибка запуска сервера: {s}\n", .{@errorName(err)});
    };
}
