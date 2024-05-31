// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
)

func GetRandomPrimesConcurrent(ctx context.Context, bitLen, numPrimes int, concurrency int) ([]*GermainSafePrime, error) {
	if bitLen < 6 {
		return nil, errors.New("safe prime size must be at least 6 bits")
	}
	if numPrimes < 1 {
		return nil, errors.New("numPrimes should be > 0")
	}

	primeCh := make(chan *GermainSafePrime, concurrency*numPrimes)
	errCh := make(chan error, concurrency*numPrimes)
	primes := make([]*GermainSafePrime, 0, numPrimes)

	waitGroup := &sync.WaitGroup{}

	defer close(primeCh)
	defer close(errCh)
	defer waitGroup.Wait()

	generatorCtx, cancelGeneratorCtx := context.WithCancel(ctx)
	defer cancelGeneratorCtx()

	for i := 0; i < concurrency; i++ {
		waitGroup.Add(1)
		runGenUnsafePrimeRoutine(
			generatorCtx, primeCh, errCh, waitGroup, rand.Reader, bitLen,
		)
	}

	needed := int32(numPrimes)
	for {
		select {
		case result := <-primeCh:
			primes = append(primes, result)
			if atomic.AddInt32(&needed, -1) <= 0 {
				return primes[:numPrimes], nil
			}
		case err := <-errCh:
			return nil, err
		case <-ctx.Done():
			return nil, ErrGeneratorCancelled
		}
	}
}

func runGenUnsafePrimeRoutine(
	ctx context.Context,
	primeCh chan<- *GermainSafePrime,
	errCh chan<- error,
	waitGroup *sync.WaitGroup,
	rand io.Reader,
	pBitLen int,
) {
	qBitLen := pBitLen - 1
	b := uint(qBitLen % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, (qBitLen+7)/8)
	q := new(big.Int)
	p := new(big.Int)

	bigMod := new(big.Int)

	go func() {
		defer waitGroup.Done()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				_, err := io.ReadFull(rand, bytes)
				if err != nil {
					errCh <- err
					return
				}

				// Clear bits in the first byte to make sure the candidate has
				// a size <= bits.
				bytes[0] &= uint8(int(1<<b) - 1)
				// Don't let the value be too small, i.e, set the most
				// significant two bits.
				// Setting the top two bits, rather than just the top bit,
				// means that when two of these values are multiplied together,
				// the result isn't ever one bit short.
				if b >= 2 {
					bytes[0] |= 3 << (b - 2)
				} else {
					// Here b==1, because b cannot be zero.
					bytes[0] |= 1
					if len(bytes) > 1 {
						bytes[1] |= 0x80
					}
				}
				// Make the value odd since an even number this large certainly
				// isn't prime.
				bytes[len(bytes)-1] |= 1

				q.SetBytes(bytes)

				// Calculate the value mod the product of smallPrimes. If it's
				// a multiple of any of these primes we add two until it isn't.
				// The probability of overflowing is minimal and can be ignored
				// because we still perform Miller-Rabin tests on the result.
				bigMod.Mod(q, smallPrimesProduct)
				mod := bigMod.Uint64()

			NextDelta:
				for delta := uint64(0); delta < 1<<20; delta += 2 {
					m := mod + delta
					for _, prime := range smallPrimes {
						if m%uint64(prime) == 0 && (qBitLen > 6 || m != uint64(prime)) {
							continue NextDelta
						}
					}

					if delta > 0 {
						bigMod.SetUint64(delta)
						q.Add(q, bigMod)
					}

					break
				}

				// There is a tiny possibility that, by adding delta, we caused
				// the number to be one bit too long. Thus we check BitLen
				// here.
				if q.ProbablyPrime(20) && q.BitLen() == qBitLen {
					if probablyPrime(q) {
						p.Mul(q, big.NewInt(2))
						p.Add(p, big.NewInt(1))

						for delta := uint64(0); delta < 1<<20; delta += 2 {
							bigMod.SetUint64(delta)
							p.Add(p, bigMod)

							if probablyPrime(p) {
								break
							}
						}

						primeCh <- &GermainSafePrime{p: p, q: q}
					}
					q = new(big.Int)
					p = new(big.Int)
				}
			}
		}
	}()
}
