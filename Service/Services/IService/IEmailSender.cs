using Service.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Service.Services.IService
{
    public interface IEmailService
    {
        Task SendEmail(EmailMessage emailData);
    }
}
