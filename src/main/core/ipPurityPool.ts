// A worker owns its selector until the complete probe/query task settles.
// Never release a slot just because its result cache was cleared.
export class IpPurityPool {
  private readonly available: number[]
  private readonly queue: Array<(slot: number) => void> = []

  constructor(size: number) {
    if (!Number.isInteger(size) || size < 1) throw new Error('Invalid IP purity pool size')
    this.available = Array.from({ length: size }, (_, index) => index)
  }

  run<T>(task: (slot: number) => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push((slot) => {
        void Promise.resolve()
          .then(() => task(slot))
          .then(
            (value) => {
              this.available.push(slot)
              this.drain()
              resolve(value)
            },
            (error: unknown) => {
              this.available.push(slot)
              this.drain()
              reject(error)
            }
          )
      })
      this.drain()
    })
  }

  private drain(): void {
    while (this.available.length > 0 && this.queue.length > 0) {
      const slot = this.available.shift()!
      const start = this.queue.shift()!
      start(slot)
    }
  }
}
