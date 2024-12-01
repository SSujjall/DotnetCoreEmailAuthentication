using System.Net;

namespace Service.Models.Response
{
    public class ServiceResponse<T>
    {
        public HttpStatusCode HttpCode { get; set; }
        public string? Message { get; set; }
        public T? Data { get; set; }
        public List<string>? Errors { get; set; }
        public bool isSuccess { get; set; } = false;
    }
}
