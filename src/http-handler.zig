const picozig = @import("picozig");
const std = @import("std");
const generateHttpResponse = picozig.generateHttpResponse;
const HttpResponse = picozig.HttpResponse;
const HttpRequest = picozig.HttpRequest;

const HttpProcessor = @import("./http-processor.zig").HttpProcessor;
const ProtocolHandler = @import("./types.zig").ProtocolHandler;

const RootHandler = struct {
    pub fn handle(request: HttpRequest, allocator: std.mem.Allocator) ![]const u8 {
        _ = request;
        return try generateHttpResponse(
            allocator,
            200,
            "text/plain",
            "Hello from test handler!",
        );
    }
    pub fn deinit() void {}
    pub fn addHandler(handler: ProtocolHandler) void {
        _ = handler;
    }
    pub fn init(allocator: std.mem.Allocator) RootHandler {
        _ = allocator;
        return RootHandler{};
    }
};

pub fn httpHandler(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    // std.debug.print("Data: {s}\n", .{data});
    var headers: [32]picozig.Header = undefined;
    const httpParams = picozig.HttpParams{
        .method = "",
        .path = "",
        .minor_version = 0,
        .num_headers = 0,
        .bytes_read = 0,
    };

    // Create HttpRequest structure
    var httpRequest = picozig.HttpRequest{
        .params = httpParams,
        .headers = &headers,
        .body = "",
    };
    _ = picozig.parseRequest(data, &httpRequest);

    var processor = HttpProcessor.init(allocator);
    defer processor.deinit();

    try processor.addHandler(.{
        .pathPrefix = "/",
        .method = "GET",
        .handleFn = RootHandler.handle,
    });

    const response = processor.processRequest(httpRequest);

    return response;
}
