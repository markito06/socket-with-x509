import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class FixedRandom extends SecureRandom {

	private static final long serialVersionUID = 6697229918988417738L;

	private MessageDigest sha;
	private byte[] state;

	public FixedRandom() {
		try {
			sha = MessageDigest.getInstance("SHA-1");
			state = sha.digest();
		} catch(final NoSuchAlgorithmException e) {
			throw new RuntimeException("can't find SHA-1!");
		}
	}

	@Override
	public void nextBytes(final byte[] bytes) {
		int off = 0;
		sha.update(state);
		while(off < bytes.length) {
			state = sha.digest();

			if(bytes.length - off > state.length) {
				System.arraycopy(state, 0, bytes, off, state.length);
			} else {
				System.arraycopy(state, 0, bytes, off, bytes.length - off);
			}

			off += state.length;

			sha.update(state);
		}
	}
}
