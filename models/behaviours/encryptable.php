<?php
class EncryptableBehavior extends ModelBehavior {
    var $fields = array();

    function setup(&$Model, $settings = array()) {
        if (!isset($Model->key)) {
            $Model->key = null;
        }
        if (isset($settings['fields'])) {
            if (is_array($settings['fields'])) {
                $this->fields = array_merge($this->fields, $settings['fields']);
            }
        }
    }

    function beforeSave(&$Model) {
        foreach ($this->fields as $alias => $fields) {
            foreach ($fields as $field) {
                if (isset($Model->data[$alias][$field])) {
                    $Model->data[$alias][$field] = $this->encrypt($Model, $Model->data[$alias][$field]);
                } elseif (isset($Model->data[$field])) {
                    $Model->data[$field] = $this->encrypt($Model, $Model->data[$field]);
                }
            }
        }
        return true;
    }

    function afterFind(&$Model, $results, $primary) {
        foreach ($this->fields as $alias => $fields) {
            foreach ($fields as $field) {
                if (isset($results[$alias][$field])) {
                    $results[$alias][$field] = $this->decrypt($Model, $results[$alias][$field]);
                } elseif (is_array($results)) {
                    foreach ($results as $key => $result) {
                       if (isset($result[$alias][$field])) {
                            $results[$key][$alias][$field] = $this->decrypt($Model, $result[$alias][$field]);
                        } elseif (isset($result[$alias]) && is_array($result[$alias])) {
                            foreach ($result[$alias] as $ke => $resul) {
                                if (isset($resul[$field])) {
                                    $results[$key][$alias][$ke][$field] = $this->decrypt($Model, $resul[$field]);
                                }
                            }
                        }
                    }
                }
            }
        }

/*	if (is_array($results)) {
		foreach ($results as $key => $result) {
			if (isset($this->fields[$key]) && is_array($result)) {
				foreach ($result as $ke => $resul) {
					if (in_array($ke, $this->fields[$key])) {
						$results[$key][$ke] = $this->decrypt($Model, $resul);
					} elseif (is_numeric($ke)) {
						
					} else {
						$results[$key]
					}
				}
			} else {
				$results[$key] = $this->afterFind($Model, $result, $primary);
			}
		}
	}*/
        return $results;
    }

    function encrypt(&$Model, $data) {
        if (!isset($Model->key)) {
            return false;
        } else {
            return mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $Model->key, $data, MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND));
        }
    }

    function decrypt(&$Model, $data) {
        if (!isset($Model->key)) {
            return false;
        } else {
            return mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $Model->key, $data, MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND));
        }
    }
}
