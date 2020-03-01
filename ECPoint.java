import java.math.BigInteger;

public class ECPoint {
    private BigInteger x;
    private BigInteger y;
    private BigInteger p;
    private BigInteger a;
    private BigInteger b;

    public ECPoint(BigInteger A, BigInteger B, BigInteger P, BigInteger X, BigInteger Y){
        p = P;
        a = A;
        b = B;
        x = X;
        y = Y;
    }

    public ECPoint(ECC curve, BigInteger X, BigInteger Y){
        p = curve.getP();
        a = curve.getA();
        b = curve.getB();
        x = X;
        y = Y;
    }
    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }
}
