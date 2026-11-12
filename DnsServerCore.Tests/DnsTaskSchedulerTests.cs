using System;
using System.Threading;
using System.Threading.Tasks;
using DnsServerCore.Dns;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class DnsTaskSchedulerTests
    {
        [Fact]
        public async Task DisposingSchedulerReleasesItsWorker()
        {
            using var scheduler = new DnsTaskScheduler("Test DNS worker");
            var started = new TaskCompletionSource<Thread>(TaskCreationOptions.RunContinuationsAsynchronously);
            var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Task operation = Task.Factory.StartNew(async () =>
            {
                started.SetResult(Thread.CurrentThread);
                await resume.Task;
            }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, scheduler).Unwrap();

            Thread worker = await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            scheduler.Dispose();
            Assert.True(worker.Join(TimeSpan.FromSeconds(5)), "The DNS scheduler worker did not exit after disposal.");

            resume.SetResult();
            await operation.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }
}
