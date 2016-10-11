/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE file at the root of the source
 * tree and available online at
 *
 * https://github.com/keeps/commons-ip
 */
package org.roda_project.commons_ip.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.ClosedByInterruptException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import javax.xml.bind.DatatypeConverter;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.io.IOUtils;
import org.roda_project.commons_ip.mets_v1_11.beans.MdSecType.MdRef;
import org.roda_project.commons_ip.model.IPConstants;
import org.roda_project.commons_ip.model.IPFile;
import org.roda_project.commons_ip.model.SIP;
import org.roda_project.commons_ip.model.ValidationEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class Utils {
  private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

  private Utils() {
  }

  public static Optional<XMLGregorianCalendar> getCurrentTime() {
    Optional<XMLGregorianCalendar> res = Optional.empty();
    try {
      GregorianCalendar c = new GregorianCalendar();
      Optional.of(DatatypeFactory.newInstance().newXMLGregorianCalendar(c));
    } catch (DatatypeConfigurationException e) {
      // do nothing & return empty
    }
    return res;
  }

  public static XMLGregorianCalendar getCurrentCalendar() throws DatatypeConfigurationException {
    GregorianCalendar gcal = new GregorianCalendar();
    gcal.setTime(new Date());
    XMLGregorianCalendar calendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(gcal);
    return calendar;
  }

  public static String generateRandomAndPrefixedUUID() {
    return METSEnums.ID_PREFIX + UUID.randomUUID().toString().toUpperCase();
  }

  public static Path copyResourceFromClasspathToDir(Class<?> resourceClass, Path dir, String resourceTempSuffix,
    String resourcePath) throws IOException, InterruptedException {
    try {
      Path resource = Files.createTempFile(dir, "", resourceTempSuffix);
      InputStream inputStream = resourceClass.getResourceAsStream(resourcePath);
      OutputStream outputStream = Files.newOutputStream(resource);
      IOUtils.copy(inputStream, outputStream);
      inputStream.close();
      outputStream.close();
      return resource;
    } catch (ClosedByInterruptException e) {
      throw new InterruptedException();
    }
  }

  public static String extractedRelativePathFromHref(MdRef mdref) {
    return extractedRelativePathFromHref(mdref.getHref());
  }

  public static String extractedRelativePathFromHref(String href) {
    String res = href;
    if (res.startsWith(IPConstants.METS_FILE_URI_PREFIX)) {
      res = res.replace(IPConstants.METS_FILE_URI_PREFIX, "");
    }
    return res;
  }

  /**
   * Deletes a directory/file
   * 
   * @param path
   *          path to the directory/file that will be deleted. in case of a
   *          directory, if not empty, everything in it will be deleted as well.
   *
   * @throws IOException
   */
  public static void deletePath(Path path) throws IOException {
    if (path == null) {
      return;
    }

    try {
      Files.delete(path);

    } catch (DirectoryNotEmptyException e) {
      LOGGER.debug("Directory is not empty. Going to delete its content as well.");
      try {
        Files.walkFileTree(path, new SimpleFileVisitor<Path>() {
          @Override
          public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
            Files.delete(file);
            return FileVisitResult.CONTINUE;
          }

          @Override
          public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
            Files.delete(dir);
            return FileVisitResult.CONTINUE;
          }

        });
      } catch (IOException e1) {
        throw e1;
      }
    } catch (IOException e) {
      throw e;
    }
  }

  /**
   * Calculates checksum, closing the inputstream in the end.
   */
  public static String calculateChecksum(InputStream is, String algorithm)
    throws NoSuchAlgorithmException, IOException {
    MessageDigest digester = MessageDigest.getInstance(algorithm);
    byte[] block = new byte[4096];
    int length;
    while ((length = is.read(block)) > 0) {
      digester.update(block, 0, length);
    }

    is.close();

    return DatatypeConverter.printHexBinary(digester.digest());
  }

  public static List<String> getFileRelativeFolders(Path basePath, Path filePath) {
    List<String> res = new ArrayList<>();
    Path relativize = basePath.relativize(filePath).getParent();
    if (relativize != null) {
      Iterator<Path> iterator = relativize.iterator();
      while (iterator.hasNext()) {
        res.add(iterator.next().toString());
      }
    }
    return res;
  }

  public static IPFile validateFile(SIP sip, Path filePath, List<String> fileRelativeFolders, String metsChecksum,
    String metsChecksumAlgorithm, String metsElementId) {
    IPFile file = null;

    try {
      String computedChecksum = Utils.calculateChecksum(Files.newInputStream(filePath), metsChecksumAlgorithm);
      if (computedChecksum.equalsIgnoreCase(metsChecksum)) {
        file = new IPFile(filePath, fileRelativeFolders).setChecksumAndAlgorithm(metsChecksum, metsChecksumAlgorithm);
      } else {
        ValidationUtils.addIssue(sip.getValidationReport(), ValidationConstants.CHECKSUMS_DIFFER,
          ValidationEntry.LEVEL.ERROR, metsElementId, metsChecksum, metsChecksumAlgorithm, computedChecksum,
          sip.getBasePath(), filePath);
      }
    } catch (NoSuchAlgorithmException | IOException e) {
      ValidationUtils.addIssue(sip.getValidationReport(), ValidationConstants.ERROR_COMPUTING_CHECKSUM,
        ValidationEntry.LEVEL.ERROR, e, sip.getBasePath(), filePath);
    }

    return file;
  }

}