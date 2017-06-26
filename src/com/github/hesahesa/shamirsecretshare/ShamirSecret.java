/*
 * Shamir's Secret Sharing implementation in Java
 * Copyright (C) 2017  Prahesa Kusuma Setia (prahesa at yahoo dot com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.github.hesahesa.shamirsecretshare;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Random;
import java.util.Set;

/**
 * Created by Prahesa K Setia on 26-Jun-17.
 */
public class ShamirSecret {
    private static int PRIME_CERTAINTY = 128;
    private BigInteger secret;
    private int threshold;
    private BigInteger modulus; // have to be a prime (or prime enough by isProbablePrime() )
    private BigInteger[] reconstructVector;

    /**
     * Construct a Shamir's Secret object, so that one can generate as many shares from the object by calling
     * appropiate method. Note that the secret have a private scope in the object
     * @param secret secret to be shared, need to be constructed as BigInteger object beforehand. The secret need
     *               to be an element of finite field Z_modulus
     * @param threshold minimum number of shares required to reconstruct secret value
     * @param modulus modulus of the finite field to operate in, need to be a prime number (or prime enough by
     *                BigInteger's isProbablePrime()
     * @throws Exception if modulus fails isProbablePrime() test, or any other Exception
     */
    public ShamirSecret(BigInteger secret, int threshold, BigInteger modulus) throws Exception {
        this.secret = secret.mod(modulus); // just to be sure, the value need to be in Z_modulus
        this.threshold = threshold;
        this.modulus = modulus;

        if(!this.modulus.isProbablePrime(PRIME_CERTAINTY)) {
            throw new Exception("modulus fails prime test by isProbablePrime(), try to use prime (or prime enough)");
        }

        this.reconstructVector = new BigInteger[threshold]; // number of coefficients = number of polynomial degree
        this.reconstructVector[0] = BigInteger.ONE; // first coefficient is for the secret

        // randomly generate polynomial P(x) by randomly generate reconstruction vector
        for(int i = 1; i <= threshold - 1; i++) {
            this.reconstructVector[i] = (new BigInteger(modulus.bitLength(), new Random())).mod(modulus);
        }
    }

    /**
     * Generate shares by specifying an index to get it. Shares are linked with their indices that they are generated
     * from, so usually we work on pairs of (index, shares) when we send the shares to interested parties.
     * @param index index to generate shares from
     * @return share associated with the index, that is the P(x) where x = index
     * @throws Exception if index is not greater or equal than 1
     */
    public BigInteger getShares(int index) throws Exception {
        if(index <= 0) {
            throw new Exception("shares index need to be greater or equal than 1");
        }
        else {
            // compute polynomial P(x) from secret and reconstruction vector
            BigInteger retVal = BigInteger.ZERO;
            retVal = retVal.add(this.secret);
            for(int i = 1; i <= threshold - 1; i++) {
                BigInteger xPowi = BigInteger.valueOf(index).modPow(BigInteger.valueOf(i), this.modulus);
                retVal = retVal.add(reconstructVector[i].multiply(xPowi).mod(this.modulus));
            }
            return retVal.mod(this.modulus);
        }
    }

    /**
     * Reconstruct the secret, that is P(0), if at least d-shares contributes to the computation. d is the threshold
     * parameter that is defined when constructing the shares in the share generation steps. If less than d shares are
     * provided, the result of this method will be undefined
     * @param sharesMap a hash map with size d that contains a pair of (index, shares).
     * @param modulus modulus of the field of operation
     * @return the secret value, the P(0). Or an undefined value if less than d shares are provided
     */
    public static BigInteger reconstructSecret(HashMap<Integer, BigInteger> sharesMap, BigInteger modulus) {
        BigInteger retVal = BigInteger.ZERO;
        for(int index : sharesMap.keySet()) {
            BigInteger lagrangeCoeff = getLagrangeCoeff(index, sharesMap.keySet(), modulus);
            BigInteger share = sharesMap.get(index);

            retVal = retVal.add(lagrangeCoeff.multiply(share).mod(modulus)).mod(modulus);
        }
        return retVal.mod(modulus);
    }

    /**
     * compute Lagrange Coefficient in order to compute secrets
     * @param i index
     * @param setIndices set of indices
     * @param modulus modulus of the field operation
     * @return the Lagrange Coefficient
     */
    private static BigInteger getLagrangeCoeff(int i, Set<Integer> setIndices, BigInteger modulus) {
        BigInteger retVal = BigInteger.ONE;
        for(int t : setIndices) {
            if(i == t) continue; // loop through set of indices except i
            BigInteger numerator = BigInteger.ZERO.subtract(BigInteger.valueOf(t)).mod(modulus);
            BigInteger denumerator = BigInteger.valueOf(i - t).mod(modulus);
            BigInteger currVal = numerator.multiply(denumerator.modInverse(modulus));

            retVal = retVal.multiply(currVal).mod(modulus);
        }
        return retVal.mod(modulus);
    }
}
