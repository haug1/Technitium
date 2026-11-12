using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace DnsServerCore.Dns
{
    internal sealed class DnsTaskScheduler : TaskScheduler, IDisposable
    {
        private readonly Channel<Task> _queue = Channel.CreateUnbounded<Task>();
        private readonly Thread[] _workers = new Thread[Environment.ProcessorCount];

        internal DnsTaskScheduler(string threadName, ThreadPriority priority = ThreadPriority.Normal)
        {
            try
            {
                for (int index = 0; index < _workers.Length; index++)
                {
                    var worker = new Thread(Run)
                    {
                        Name = threadName,
                        IsBackground = true,
                        Priority = priority
                    };
                    _workers[index] = worker;
                    worker.Start();
                }
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public override int MaximumConcurrencyLevel => _workers.Length;

        protected override IEnumerable<Task> GetScheduledTasks() => throw new NotSupportedException();

        protected override void QueueTask(Task task)
        {
            // Work already in flight can resume on this scheduler after the DNS server stops.
            if (!_queue.Writer.TryWrite(task))
                ThreadPool.UnsafeQueueUserWorkItem(task => TryExecuteTask(task), task, preferLocal: false);
        }

        protected override bool TryExecuteTaskInline(Task task, bool taskWasPreviouslyQueued) =>
            Array.IndexOf(_workers, Thread.CurrentThread) >= 0 && TryExecuteTask(task);

        private void Run()
        {
            ChannelReader<Task> reader = _queue.Reader;
            try
            {
                while (true)
                {
                    ValueTask<Task> next = reader.ReadAsync();
                    TryExecuteTask(next.IsCompletedSuccessfully ? next.Result : next.AsTask().GetAwaiter().GetResult());
                }
            }
            catch (ChannelClosedException)
            { }
        }

        // Completing the queue wakes idle workers and allows pending tasks to drain.
        public void Dispose() => _queue.Writer.TryComplete();
    }
}
