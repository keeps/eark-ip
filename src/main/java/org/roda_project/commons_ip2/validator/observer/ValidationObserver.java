package org.roda_project.commons_ip2.validator.observer;

/**
 * @author João Gomes <jgomes@keep.pt>
 */

public interface ValidationObserver {

  void notifyValidationStart();

  void notifyStartValidationModule(String moduleName, String ID);


}