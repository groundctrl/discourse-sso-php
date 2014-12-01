<?php namespace Ctrl\Discourse\Sso;

class DataObject implements \ArrayAccess, \Countable, \IteratorAggregate
{
    /** @var array */
    protected $data;

    /**
     * QueryString Constructor.
     *
     * @param array $data
     */
    public function __construct(array $data = [])
    {
        $this->data = $data;
    }

    /**
     * @return array
     */
    public function all()
    {
        return $this->data;
    }

    /**
     * {@inheritDoc}
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->data);
    }

    /**
     * {@inheritDoc}
     */
    public function offsetExists($offset)
    {
        return array_key_exists($offset, $this->data);
    }

    /**
     * {@inheritDoc}
     */
    public function offsetGet($offset)
    {
        return array_key_exists($offset, $this->data) ? $this->data[$offset] : null;
    }

    /**
     * {@inheritDoc}
     */
    public function offsetSet($offset, $value)
    {
        $this->data[$offset] = $value;
    }

    /**
     * {@inheritDoc}
     */
    public function offsetUnset($offset)
    {
        if (array_key_exists($offset, $this->data)) {
            unset($this->data[$offset]);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function count()
    {
        return count($this->data);
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return QueryString::normalize($this->data);
    }
}
