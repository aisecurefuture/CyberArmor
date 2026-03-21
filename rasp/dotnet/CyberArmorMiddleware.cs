using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace CyberArmor.RASP
{
    public static class CyberArmorExtensions
    {
        public static IServiceCollection AddCyberArmorRasp(this IServiceCollection services, Action<CyberArmorOptions> configure)
        {
            return CyberArmorExtensions.AddCyberArmorRasp(services, configure);
        }

        public static IApplicationBuilder UseCyberArmorRasp(this IApplicationBuilder app)
        {
            return CyberArmorExtensions.UseCyberArmorRasp(app);
        }
    }
}
