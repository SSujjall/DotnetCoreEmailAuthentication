using System.Net;

namespace API.Models.Response
{
    public class CommonResponseModel
    {
        public HttpStatusCode ResponseCode { get; set; }
        public object? Message { get; set; }
        public object? Data { get; set; }
        public object? Errors { get; set; }
    }
}
