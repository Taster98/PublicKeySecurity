import java.math.BigInteger;
import java.util.Random;

public class RSA {
    private BigInteger p;
    private BigInteger q;
    private BigInteger n;
    private BigInteger phi;
    private BigInteger e;
    private BigInteger d;

    public Triple<BigInteger,BigInteger,BigInteger> ExtendedEuclid(BigInteger a, BigInteger b){
        if(b.equals(BigInteger.valueOf(0))){
            return new Triple<>(a, BigInteger.valueOf(1), BigInteger.valueOf(0));
        }else{
            Triple<BigInteger,BigInteger,BigInteger> t1 = ExtendedEuclid(b,a.mod(b));
            int special = (int) Math.floor((a.divide(b)).intValue());

            return new Triple<>(t1.getFirst(), t1.getThird(), t1.getSecond().subtract(BigInteger.valueOf(special)).multiply(t1.getThird()));
        }
    }

    public RSA(BigInteger P, BigInteger Q){
        p=P;
        q=Q;
        n = p.multiply(q);
        phi = (p.subtract(BigInteger.valueOf(1))).multiply((q.subtract(BigInteger.valueOf(1))));
        Random r = new Random();
        BigInteger aux = BigInteger.valueOf(r.nextInt(((phi.subtract(BigInteger.valueOf(1))).intValue() - 3) + 1) + 3);
        while(!(aux.gcd(phi).equals(BigInteger.valueOf(1)))){
            aux = BigInteger.valueOf(r.nextInt(((phi.subtract(BigInteger.valueOf(1))).intValue() - 3) + 1) + 3);
        }
        e = aux;
        d = e.modInverse(phi);
    }

    public BigInteger getE(){
        return e;
    }
    public BigInteger getN(){
        return n;
    }
    public BigInteger getD(){
        return d;
    }
    public BigInteger Encrypt(BigInteger msg, BigInteger n, BigInteger e){
        return (msg.modPow(e,n));
    }

    public BigInteger Decrypt(BigInteger crt, BigInteger n, BigInteger d){
        return (crt.modPow(d,n));
    }
}
