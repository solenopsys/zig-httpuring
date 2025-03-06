const std = @import("std");
const Allocator = std.mem.Allocator;
const response_generator = @import("picozig");
const HttpRequest = @import("picozig").HttpRequest;
const HttpResponse = @import("picozig").HttpResponse;
const HttpParams = @import("picozig").HttpParams;

const ProtocolHandler = @import("./types.zig").ProtocolHandler;

pub const HttpProcessor = struct {
    allocator: Allocator,
    handlers: std.ArrayList(ProtocolHandler),

    pub fn init(allocator: Allocator) HttpProcessor {
        return .{
            .allocator = allocator,
            .handlers = std.ArrayList(ProtocolHandler).init(allocator),
        };
    }

    pub fn deinit(self: *HttpProcessor) void {
        self.handlers.deinit();
    }

    pub fn addHandler(self: *HttpProcessor, handler: ProtocolHandler) !void {
        try self.handlers.append(handler);
    }

    pub fn processRequest(self: *HttpProcessor, request: HttpRequest) ![]const u8 {
        // Ищем подходящий обработчик
        for (self.handlers.items) |handler| {
            if (std.mem.startsWith(u8, request.params.path, handler.pathPrefix))
            // and
            //   std.mem.eql(u8, request.params.method, handler.method))
            {
                return try handler.handleFn(request, self.allocator);
            }
        }

        // Обработчик не найден - возвращаем 404
        return try response_generator.generateHttpResponse(
            self.allocator,
            404,
            "text/plain",
            "Not Found",
        );
    }
};

// Пример использования:

test "HttpProcessor basic usage" {
    const TestHandler = struct {
        pub fn handle(request: HttpRequest, allocator: Allocator) ![]const u8 {
            _ = request;
            return try response_generator.generateHttpResponse(
                allocator,
                200,
                "text/plain",
                "Hello from test handler!",
            );
        }
    };

    const allocator = std.testing.allocator;

    var processor = HttpProcessor.init(allocator);
    defer processor.deinit();

    try processor.addHandler(.{
        .pathPrefix = "/api/test",
        .method = "GET",
        .handleFn = TestHandler.handle,
    });

    const params = HttpParams{
        .method = "GET",
        .path = "/api/test",
        .minor_version = -1,
        .num_headers = 0,
        .bytes_read = 0,
    };

    const request = HttpRequest{
        .params = params,
        .headers = undefined,
        .body = "",
    };

    const response = try processor.processRequest(request);
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Hello from test handler!") != null);
}

test "404 Not Found" {
    const TestHandler = struct {
        pub fn handle(request: HttpRequest, allocator: Allocator) ![]const u8 {
            _ = request;
            return try response_generator.generateHttpResponse(
                allocator,
                200,
                "text/plain",
                "Hello from test handler!",
            );
        }
    };

    const allocator = std.testing.allocator;

    var processor = HttpProcessor.init(allocator);
    defer processor.deinit();

    try processor.addHandler(.{
        .pathPrefix = "/api/test",
        .method = "GET",
        .handleFn = TestHandler.handle,
    });

    const params = HttpParams{
        .method = "GET",
        .path = "/main/test/something",
        .minor_version = -1,
        .num_headers = 0,
        .bytes_read = 0,
    };

    const request = HttpRequest{
        .params = params,
        .headers = undefined,
        .body = "",
    };

    const response = try processor.processRequest(request);
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "404 Not Found") != null);
}
