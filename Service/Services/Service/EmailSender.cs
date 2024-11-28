using MimeKit;
using Service.Models;
using Service.Services.IService;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Service.Services.Service
{
    public class EmailService : IEmailService
    {
        public Task SendEmail(EmailMessage emailData)
        {
            var message = new MimeMessage();
            return null;
        }
    }
}
