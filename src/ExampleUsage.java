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
import com.github.hesahesa.shamirsecretshare.ShamirSecret;

import java.math.BigInteger;
import java.util.HashMap;

/**
 * Created by Prahesa K Setia on 26-Jun-17.
 */
public class ExampleUsage {
    public static void main(String[] args) throws Exception {
        BigInteger theSecret = new BigInteger("1024");
        int threshold = 3;
        BigInteger modulus = new BigInteger("1000003");

        ShamirSecret shamirSecret = new ShamirSecret(theSecret, threshold, modulus);

        BigInteger[] shares = new BigInteger[6];
        shares[1] = shamirSecret.getShares(1);
        shares[2] = shamirSecret.getShares(2);
        shares[3] = shamirSecret.getShares(3);
        shares[4] = shamirSecret.getShares(4);
        shares[5] = shamirSecret.getShares(5);

        HashMap<Integer, BigInteger> computedShares = new HashMap<>();
        computedShares.put(1, shares[1]);
        computedShares.put(4, shares[4]);
        computedShares.put(5, shares[5]);

        BigInteger computedSecret = ShamirSecret.reconstructSecret(computedShares, modulus);

        System.out.println("index\tshares");
        System.out.println(""+1+"\t\t"+shares[1]);
        System.out.println(""+2+"\t\t"+shares[2]);
        System.out.println(""+3+"\t\t"+shares[3]);
        System.out.println(""+4+"\t\t"+shares[4]);
        System.out.println(""+5+"\t\t"+shares[5]);
        System.out.println("computed secret from shares: "+computedSecret);
    }
}
