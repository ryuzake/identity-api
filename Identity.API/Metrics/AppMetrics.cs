using Prometheus;

namespace Identity.API.Metrics;

public static class AppMetrics
{
    public static readonly Counter RegistrationsTotal = Prometheus.Metrics
        .CreateCounter("identity_registrations_total", "Total number of user registrations.");

    public static readonly Counter LoginsTotal = Prometheus.Metrics
        .CreateCounter("identity_logins_total", "Total number of login attempts.",
            new CounterConfiguration { LabelNames = new[] { "result" } });

    public static readonly Gauge ActiveUsers = Prometheus.Metrics
        .CreateGauge("identity_active_users", "Total number of registered users.");
}
