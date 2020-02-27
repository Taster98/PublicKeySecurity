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

    //public void setX(BigInteger x) {
     //   this.x = x;
//    }

    public BigInteger getY() {
        return y;
    }

    /*public void setY(BigInteger y) {
        this.y = y;
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public BigInteger getA() {
        return a;
    }

    public void setA(BigInteger a) {
        this.a = a;
    }

    public BigInteger getB() {
        return b;
    }

    public void setB(BigInteger b) {
        this.b = b;
    }*/

}
